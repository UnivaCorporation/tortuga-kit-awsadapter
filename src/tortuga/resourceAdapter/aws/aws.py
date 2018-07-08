# Copyright 2008-2018 Univa Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pylint: disable=no-member,logging-not-lazy,logging-format-interpolation

import csv
import itertools
import json
import os
import random
import shlex
import socket
import sys
import xml.etree.cElementTree as ET
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Tuple, Union
from typing.io import TextIO

import boto
import boto.ec2
import boto.vpc
import gevent
import gevent.queue
import zmq
from boto.ec2.connection import EC2Connection
from boto.ec2.networkinterface import (NetworkInterfaceCollection,
                                       NetworkInterfaceSpecification)
from sqlalchemy.orm.session import Session

from tortuga.addhost.addHostServerLocal import AddHostServerLocal
from tortuga.db.models.hardwareProfile import HardwareProfile
from tortuga.db.models.instanceMapping import InstanceMapping
from tortuga.db.models.nic import Nic
from tortuga.db.models.node import Node
from tortuga.db.models.softwareProfile import SoftwareProfile
from tortuga.db.nodesDbHandler import NodesDbHandler
from tortuga.exceptions.commandFailed import CommandFailed
from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.exceptions.invalidArgument import InvalidArgument
from tortuga.exceptions.nicNotFound import NicNotFound
from tortuga.exceptions.nodeNotFound import NodeNotFound
from tortuga.exceptions.operationFailed import OperationFailed
from tortuga.exceptions.resourceNotFound import ResourceNotFound
from tortuga.exceptions.tortugaException import TortugaException
from tortuga.node import state
from tortuga.objects import resourceadapter_settings as settings
from tortuga.resourceAdapter.resourceAdapter import DbManager, ResourceAdapter
from tortuga.utility.helper import str2bool

from .exceptions import AWSOperationTimeoutError
from .helpers import _get_encoded_list, ec2_get_root_block_devices
from .launchRequest import LaunchRequest, init_node_request_queue


class Aws(ResourceAdapter):
    """
    AWS resource adapter

    """
    __adaptername__ = 'aws'

    LAUNCH_INITIAL_SLEEP_TIME = 10.0

    TEST_MODE = False

    settings = {
        'ami': settings.StringSetting(
            required=True,
            description='AMI ID to use for launching node instances'
        ),
        'awsAccessKey': settings.StringSetting(
            required=True,
            secret=True,
            description='AWS API access key',
            mutually_exclusive=['iam_instance_profile_name'],
            requires=['awsSecretKey']
        ),
        'awsSecretKey': settings.StringSetting(
            required=True,
            secret=True,
            description='AWS API secret key',
            mutually_exclusive=['iam_instance_profile_name'],
            requires=['awsAccessKey']
        ),
        'block_device_map': settings.StringSetting(
            description='Block device map for new node instances'
        ),
        'cloud_init': settings.BooleanSetting(
            description='Enable/disable cloud-init script user-data',
            default=True
        ),
        'cloud_init_script_template': settings.FileSetting(
            description='Path to cloud init script',
            mutually_exclusive=['user_data_script_template']
        ),
        'user_data_script_template': settings.FileSetting(
            description='Path to user date template script',
            mutually_exclusive=['cloud_init_script_template']
        ),
        'endpoint': settings.StringSetting(
            description='AWS (or compatible) API endpoint'
        ),
        'iam_instance_profile_name': settings.StringSetting(
            description='IAM Instance Profile (IIP) name to associate with '
                        'new node instance(s)',
            mutually_exclusive=['awsAccessKey', 'awsSecretKey']
        ),
        'instancetype': settings.StringSetting(
            description='AWS compute node instance type',
            required=True
        ),
        'keypair': settings.StringSetting(
            description='Name of AWS SSH keypair to install on new node '
                        'instances',
            required=True
        ),
        'override_dns_domain': settings.BooleanSetting(
            description='Allow the compute node bootstrap process to manage '
                        '/etc/resolv.conf'
        ),
        'dns_search': settings.StringSetting(
            description='The DNS search order to be configured on new node '
                        'instances',
            requires=['override_dns_domain']
        ),
        'dns_options': settings.StringSetting(
            description='specifies the "options" field in /etc/resolv.conf '
                        'on new node instances',
            requires=['override_dns_domain']
        ),
        'dns_nameservers': settings.StringSetting(
            description='specifies the "nameservers" field in '
                        '/etc/resolv.conf on compute node instances and is '
                        'a space-separated list of IP addresses',
            requires=['override_dns_domain']
        ),
        'use_domain_from_dhcp_option_set': settings.BooleanSetting(
            description='use domain specified in DHCP option set',
        ),
        'region': settings.StringSetting(
            description='AWS region',
            default='us-east-1'
        ),
        'zone': settings.StringSetting(
            description='AWS zone'
        ),
        'placementgroup': settings.StringSetting(
            description='AWS placement group'
        ),
        'securitygroup': settings.StringSetting(
            description='AWS security group. This security group must allow '
                        'unrestricted access between the Tortuga installer '
                        'and compute instances.'
        ),
        'subnet_id': settings.StringSetting(
            description='AWS subnet ID for new node instances'
        ),
        'tags': settings.StringSetting(
            description='AWS tags, a space separated list in the form of '
                        'key=value'
        ),
        'use_instance_hostname': settings.BooleanSetting(
            description='When true, the AWS-assigned host name will be '
                        'used as the host name for new instances'
        ),
        'vcpus': settings.IntegerSetting(
            description='The of virtual CPUs for the resource adapter '
                        'configuration profile'
        ),
        'launch_timeout': settings.IntegerSetting(
            description='Timeout (in seconds) of the launch request',
            default=300
        )
    }

    # Default time in seconds before creates will return even if not
    # completed
    DEFAULT_CREATE_TIMEOUT = 900

    # Time (seconds) between attempts to update EC2 instance status to
    # avoid thrashing
    DEFAULT_SLEEP_TIME = 5

    def __init__(self, addHostSession: Optional[str] = None) -> None:
        super(Aws, self).__init__(addHostSession=addHostSession)

        # Initialize internal flags
        self.__runningOnEc2 = None
        self.__installer_ip: Union[str, None] = None

        self.__launch_wait_queue = gevent.queue.JoinableQueue()

    def getEC2Connection(self, configDict: Dict[str, Any]) -> EC2Connection:
        connectionArgs = dict(
            aws_access_key_id=configDict['awsaccesskey'],
            aws_secret_access_key=configDict['awssecretkey'],
        )

        if 'proxy_host' in configDict:
            self._logger.debug('Using proxy for AWS (%s:%s)' % (
                configDict['proxy_host'], configDict['proxy_port']))

            connectionArgs['proxy'] = configDict['proxy_host']
            connectionArgs['proxy_port'] = configDict['proxy_port']

            # Pass these arguments verbatim to the boto library
            if 'proxy_user' in configDict:
                connectionArgs['proxy_user'] = configDict['proxy_user']

            if 'proxy_pass' in configDict:
                connectionArgs['proxy_pass'] = configDict['proxy_pass']

        return boto.ec2.connect_to_region(configDict['region'],
                                          **connectionArgs)

    def _normalize_resource_adapter_config(
            self, default_config: Dict[str, str],
            override_config: Optional[Dict[str, str]]) -> dict:
        """
        'default_config' and 'override_config' are key-value pairs
        extracted from the resource adapter configuration.
        """

        configDict = dict.copy(default_config or {})

        # 'user_data_script_template' and 'cloud_init_script_template'
        # are mutually exclusive arguments. Ensure resource adapter
        # configuration overrides default settings accordingly.

        if override_config:
            if 'user_data_script_template' in override_config and \
                    'cloud_init_script_template' in default_config:
                del default_config['cloud_init_script_template']

            if 'cloud_init_script_template' in override_config and \
                    'user_data_script_template' in default_config:
                del configDict['user_data_script_template']

            configDict.update(override_config)

        config = {}

        if 'ami' in configDict:
            config['ami'] = configDict['ami']

        reqd_settings = ['ami']

        missing = set(reqd_settings) - set(config.keys())

        if missing:
            errmsg = 'Missing required EC2 configuration parameter(s): %s' % (
                ' '.join(missing))

            self.getLogger().error(errmsg)

            raise ConfigurationError(errmsg)

        # Copy values from src dict to dst dict

        # Configuration - required items
        for key in reqd_settings:
            if key not in configDict:
                continue

            config[key] = configDict[key]

        # Configuration - optional items
        optional_settings = [
            'keypair',
            'instancetype',
            'region',
            'securitygroup',
            'sleeptime',
            'zone',
            'placementgroup',
            'endpoint',
            'user_data_script_template',
            'cloud_init',
            'cloud_init_script_template',
            'subnet_id', 'vpc_gateway',
            'use_instance_hostname',
            'awsaccesskey',
            'awssecretkey',
            'monitoring_enabled',
            'ebs_optimized',
            'associate_public_ip_address',
            'use_custom_dns_domain',
            'override_dns_domain',
            'dns_search',
            'dns_domain',
            'dns_nameservers',
            'dns_options',
            'iam_instance_profile_name',
            'use_domain_from_dhcp_option_set',
            'installer_ip',
            'tags',
            'use_tags',
            'use_reverse_dns_hostname',
        ]

        for key in optional_settings:
            config[key] = configDict[key] if key in configDict else None

        # other settings
        addl_optional_settings = [
            'aki',
            'ari',
            'proxy_host',
            'proxy_port',
            'proxy_user',
            'proxy_pass',
            'block_device_map',
        ]

        for key in addl_optional_settings:
            if key in configDict:
                config[key] = configDict[key]

        all_valid_settings = set(reqd_settings + optional_settings + \
            addl_optional_settings)

        current_settings_keys = set(configDict.keys())

        unknown_settings = current_settings_keys - all_valid_settings
        if unknown_settings:
            raise ConfigurationError(
                'Unsupported AWS resource adapter setting{}: {}'.format(
                    's' if len(unknown_settings) > 1 else '',
                    ' '.join(unknown_settings))
            )

        if 'awsaccesskey' in configDict:
            # Validate 'awsaccesskey' and 'awssecretkey'
            if not configDict['awsaccesskey'].strip():
                raise ConfigurationError(
                    'AWS configuration item \'awsaccesskey\' cannot be'
                    ' blank/empty')

            if 'awssecretkey' not in configDict or \
                    not configDict['awssecretkey'].strip():
                raise ConfigurationError(
                    'AWS configuration item \'awssecretkey\' cannot be'
                    ' blank/empty')

        if config['region'] is None:
            # default to us-east1-region
            config['region'] = 'us-east-1'

        if config['installer_ip'] is None:
            config['installer_ip'] = self.installer_public_ipaddress

        # Security group has to be a list
        if config['securitygroup']:
            vals = config['securitygroup'].split(',')

            config['securitygroup'] = [
                securitygroup.strip() for securitygroup in vals
            ]

        # Special handling for configuration options which aren't strings
        config['createtimeout'] = int(configDict['createtimeout']) \
            if 'createtimeout' in configDict else self.DEFAULT_CREATE_TIMEOUT

        config['launch_timeout'] = int(configDict['launch_timeout']) \
            if 'launch_timeout' in configDict else 300

        config['sleeptime'] = int(configDict['sleeptime']) \
            if 'sleeptime' in configDict else self.DEFAULT_SLEEP_TIME

        config['monitoring_enabled'] = self.__convert_to_bool(
            config['monitoring_enabled'], default=False)

        config['ebs_optimized'] = self.__convert_to_bool(
            config['ebs_optimized'], default=False)

        if 'cloud_init_script_template' in configDict and \
                configDict['cloud_init_script_template'] and \
                'user_data_script_template' in configDict and \
                configDict['user_data_script_template']:
            raise ConfigurationError(
                '\'cloud_init_script_template\' and'
                ' \'user_data_script_template\' settings are mutually'
                ' exclusive')

        if 'user_data_script_template' in configDict and \
                configDict['user_data_script_template']:
            try:
                config['user_data_script_template'] = \
                    self._get_config_file_path(
                        configDict['user_data_script_template']
                    )

                del config['cloud_init_script_template']

                # automatically toggle 'cloud_init' flag
                config['cloud_init'] = True
            except ConfigurationError as exc:
                raise ConfigurationError(
                    'Invalid \'user_data_script_template\''
                    ' setting: {0}'.format(exc)
                )

        elif 'cloud_init_script_template' in configDict and \
                configDict['cloud_init_script_template']:
            try:
                config['cloud_init_script_template'] = \
                    self._get_config_file_path(
                        configDict['cloud_init_script_template']
                    )

                del config['user_data_script_template']

                config['cloud_init'] = True
            except ConfigurationError as exc:
                raise ConfigurationError(
                    'Invalid \'cloud_init_script_template\' '
                    'setting: {0}'.format(exc)
                )
        else:
            config['cloud_init'] = False

            del config['user_data_script_template']
            del config['cloud_init_script_template']

        if 'vpn' in configDict:
            raise ConfigurationError(
                'OpenVPN support is obsolete; remove \'vpn\' setting'
                ' from resource adapter configuration')

        # 'use_instance_hostname' is enabled by default when Tortuga is
        # hosted on EC2.
        config['use_instance_hostname'] = self.__convert_to_bool(
            configDict.get('use_instance_hostname'), default=True
        )

        # Support for instance tagging is enabled by default
        config['use_tags'] = self.__convert_to_bool(
            config['use_tags'], default=True)

        config['use_reverse_dns_hostname'] = \
            str2bool(configDict['use_reverse_dns_hostname']) \
            if 'use_reverse_dns_hostname' in configDict else False

        # if 'use_reverse_dns_hostname' is set, ensure 'use_instance_hostname'
        # is also set
        if config['use_reverse_dns_hostname'] and \
            not config['use_instance_hostname']:
                config['use_instance_hostname'] = True

        # Parse out user-defined tags
        config['tags'] = {}

        if 'tags' in configDict and configDict['tags']:
            # Support tag names/values containing spaces and tags without a
            # value.
            for tagdef in shlex.split(configDict['tags']):
                key, value = tagdef.rsplit('=', 1) \
                    if '=' in tagdef else (tagdef, '')

                config['tags'][key] = value

            config['use_tags'] = True

        if 'block_device_map' in configDict:
            config['block_device_map'] = self.__process_block_device_map(
                configDict['block_device_map'])

        # Convert 'associate_public_ip_address' to bool
        config['associate_public_ip_address'] = self.__convert_to_bool(
            config['associate_public_ip_address'], default=True)

        if 'use_custom_dns_domain' in config and \
                config['use_custom_dns_domain']:
            self.getLogger().warning(
                'Setting \'use_custom_dns_domain\' is deprecated.'
                ' Please use \'override_dns_domain\' to remove this'
                ' warning.')

            config['override_dns_domain'] = self.__convert_to_bool(
                config['use_custom_dns_domain'])
        else:
            config['override_dns_domain'] = self.__convert_to_bool(
                config['override_dns_domain'])

        del config['use_custom_dns_domain']

        if config['override_dns_domain']:
            if config['dns_search']:
                self.getLogger().warning(
                    'Setting \'dns_search\' is deprecated. Please use'
                    ' \'dns_domain\' to remove this warning.')

                # Map deprecated 'dns_search' setting to 'dns_domain'
                config['dns_domain'] = config['dns_search']
            else:
                # ensure 'dns_domain' is set
                if not config['dns_domain']:
                    config['dns_domain'] = self.private_dns_zone

            config['dns_nameservers'] = config['dns_nameservers'].split(' ') \
                if config['dns_nameservers'] else []

            if not config['dns_nameservers']:
                # Ensure 'dns_nameservers' defaults to the Tortuga installer
                # as the DNS nameserver
                config['dns_nameservers'].append(
                    config['installer_ip']
                    if config['installer_ip'] else
                    self.installer_public_ipaddress)

        del config['dns_search']

        # Attempt to use DNS setting from DHCP Option Set associated with VPC
        config['use_domain_from_dhcp_option_set'] = self.__convert_to_bool(
            config['use_domain_from_dhcp_option_set'], default=False,
        )
        if config['subnet_id'] and config['use_domain_from_dhcp_option_set']:
            # Attempt to look up default DNS domain from DHCP options set
            domain = self.__get_vpc_default_domain(config)
            if domain:
                self.getLogger().info(
                    'Using default domain [%s] from DHCP option set',
                    domain
                )

                config['dns_domain'] = domain
                config['override_dns_domain'] = True

        if 'vcpus' in configDict:
            try:
                config['vcpus'] = int(configDict['vcpus'])
            except ValueError:
                raise ConfigurationError(
                    'Invalid/malformed value for \'vcpus\'')

        if config['override_dns_domain'] is None:
            config['override_dns_domain'] = False

        if config['override_dns_domain']:
            self.getLogger().debug(
                'Using DNS domain {0} for compute nodes'.format(
                    config['dns_domain']))

        return config

    def __get_vpc_default_domain(self, config: dict) -> str: \
            # pylint: disable=no-self-use
        """Returns custom DNS domain associated with DHCP option set,
        otherwise returns None

        Raises:
            ConfigurationError
        """

        try:
            vpcconn = boto.vpc.connect_to_region(
                config['region'],
                aws_access_key_id=config['awsaccesskey'],
                aws_secret_access_key=config['awssecretkey']
            )
        except boto.exception.NoAuthHandlerFound:
            raise ConfigurationError(
                'Unable to authenticate AWS connection: check credentials')

        try:
            # Look up configured subnet_id
            subnet = vpcconn.get_all_subnets(
                subnet_ids=[config['subnet_id']])[0]

            # Look up VPC
            vpc = vpcconn.get_all_vpcs(vpc_ids=[subnet.vpc_id])[0]

            # Look up DHCP options set
            dhcp_options_set = vpcconn.get_all_dhcp_options(
                dhcp_options_ids=[vpc.dhcp_options_id])[0]

            if 'domain-name' not in dhcp_options_set.options:
                return None

            # Use first defined default domain
            default_domain = dhcp_options_set.options['domain-name'][0]

            # Default EC2 assigned domain depends on region
            ec2_default_domain = 'ec2.internal' \
                if config['region'] == 'us-east-1' else \
                '{0}.compute.internal'.format(config['region'].name)

            return default_domain \
                if default_domain != ec2_default_domain else None
        except boto.exception.EC2ResponseError as exc:
            raise ConfigurationError('AWS error: {0}'.format(exc.message))

    def __convert_to_bool(self, value: str,
                          default: Optional[bool] = None) -> bool: \
            # pylint: disable=no-self-use
        return value.lower().startswith('t') \
            if value is not None else default

    def __process_block_device_map(self, cfg_block_device_map: str) \
            -> boto.ec2.blockdevicemapping.BlockDeviceMapping:
        """
        Raises:
            ConfigurationError
        """

        bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()

        for entry in cfg_block_device_map.split(','):
            try:
                device, mapping = entry.split('=', 1)
            except ValueError:
                raise ConfigurationError(
                    'Malformed block device mapping entry: %s' % (entry))

            self.getLogger().debug(
                '__process_block_device_map(): device=[%s]' % (device))

            elements = mapping.split(':')
            if not elements:
                self.getLogger().debug(
                    'Ignoring malformed mapping for device [%s]' % (device))

                continue

            bdt = boto.ec2.blockdevicemapping.BlockDeviceType()

            if elements[0].startswith('none'):
                self.getLogger().warning(
                    'Suppressing existing device mapping for [%s]' % (device))

                bdt.no_device = True
            elif elements[0].startswith('ephemeral'):
                bdt.ephemeral_name = elements[0]
            else:
                # [snapshot-id]:[volume-size]:[delete-on-termination]:
                # [volume-type[:iops]]:[encrypted]

                if elements[0]:
                    bdt.snapshot_id = elements[0]

                arglen = len(elements)

                if arglen > 1 and elements[1]:
                    bdt.size = elements[1]

                if arglen > 2 and elements[2]:
                    bdt.delete_on_termination = \
                        elements[2].lower() == 'true'

                if arglen > 3 and elements[3]:
                    bdt.volume_type = elements[3]

                    if bdt.volume_type not in ('standard', 'gp2', 'io1'):
                        self.getLogger().warning(
                            'Unrecognized block device volume type'
                            ' [%s]' % (bdt.volume_type))

                    if bdt.volume_type == 'io1':
                        if arglen < 5:
                            raise ConfigurationError(
                                'Malformed block device mapping'
                                ' specification for device [%s]. Missing'
                                ' value for \'iops\'' % (device))

                        try:
                            bdt.iops = int(elements[4])
                        except ValueError:
                            raise ConfigurationError(
                                'Malformed value [%s] for IOPS. Must be an'
                                ' integer value.' % (elements[4]))

                # Determine value of 'encrypted' flag (either undefined or the
                # string 'encrypted')
                if (arglen > 4 and elements[4] and bdt.volume_type != 'io1') or \
                        (arglen > 5 and bdt.volume_type == 'io1' and elements[5]):
                    encrypted_str = elements[5].lower() \
                        if bdt.volume_type == 'io1' else elements[4].lower()

                    # Value must be empty or 'encrypted'
                    if encrypted_str and encrypted_str != 'encrypted':
                        raise ConfigurationError(
                            'Malformed \'encrypted\' flag [%s]. Must be'
                            ' undefined (for no encryption) or'
                            ' \'encrypted\'' % (encrypted_str))

                    bdt.encrypted = encrypted_str == 'encrypted'

            # Add device mapping
            bdm[device] = bdt

        self.getLogger().debug('block device map: %s' % (bdm))

        return bdm

    def __get_instance_by_instance_id(self, conn: EC2Connection,
                                      instance_id: str) \
            -> Union[boto.ec2.instance.Instance, None]:
        result = conn.get_only_instances(instance_ids=[instance_id])
        if not result:
            return None

        return result[0]

    def start(self, addNodesRequest: dict, dbSession: Session,
              dbHardwareProfile: HardwareProfile,
              dbSoftwareProfile: Optional[SoftwareProfile] = None) \
            -> List[Node]:
        """
        Create one or more nodes

        Raises:
            InvalidArgument
        """

        self.getLogger().debug(
            'start(addNodeRequest=[%s], dbSession=[%s],'
            ' dbHardwareProfile=[%s], dbSoftwareProfile=[%s])' % (
                addNodesRequest, dbSession, dbHardwareProfile.name,
                dbSoftwareProfile.name if dbSoftwareProfile else '(none)'))

        # Get connection to AWS
        launch_request = LaunchRequest()
        launch_request.hardwareprofile = dbHardwareProfile
        launch_request.softwareprofile = dbSoftwareProfile
        launch_request.addNodesRequest = addNodesRequest

        cfgname = addNodesRequest.get('resource_adapter_configuration')
        if cfgname is None or cfgname == 'default':
            # use default resource adapter configuration, if set
            cfgname = dbHardwareProfile.default_resource_adapter_config.name \
                if dbHardwareProfile.default_resource_adapter_config else None

        launch_request.configDict = self.getResourceAdapterConfig(cfgname)

        launch_request.conn = self.getEC2Connection(
            launch_request.configDict)

        if 'spot_instance_request' in addNodesRequest:
            return self.request_spot_instances(
                dbSession, launch_request)

        if 'nodeDetails' in addNodesRequest and \
                addNodesRequest['nodeDetails']:
            # Instances already exist, create node records
            if 'metadata' in addNodesRequest['nodeDetails'][0] and \
                    'ec2_instance_id' in \
                    addNodesRequest['nodeDetails'][0]['metadata']:
                # inserting nodes based on metadata
                return self.__insert_nodes(dbSession, launch_request)

        nodes = self.__add_active_nodes(dbSession, launch_request) \
            if dbSoftwareProfile and not dbSoftwareProfile.isIdle else \
                self.__add_idle_nodes(dbSession, launch_request)

        # This is a necessary evil for the time being, until there's
        # a proper context manager implemented.
        self.addHostApi.clear_session_nodes(nodes)

        return nodes

    def __add_active_nodes(self, session: Session,
                           launch_request: LaunchRequest) -> List[Node]:
        """
        Add active nodes
        """

        if launch_request.configDict['use_instance_hostname']:
            # Create instances before node records. We need to the
            # instance to exist to get the host name for the node
            # record.
            self.__prelaunch_instances(session, launch_request)
        else:
            # Create node records before instances
            self.__add_hosts(session, launch_request)

        return self.__process_node_request_queue(session, launch_request)

    def __insert_nodes(self, session: Session,
                       launch_request: LaunchRequest) -> List[Node]:
        """
        Directly insert nodes with pre-existing AWS instances

        This is primarily used for supporting spot instances where an
        AWS instance exists before the Tortuga associated node record.
        """

        self.getLogger().debug(
            'Inserting {} node(s)'.format(
                len(launch_request.addNodesRequest['nodeDetails']))
        )

        nodes: List[Node] = []

        for nodedetail in launch_request.addNodesRequest['nodeDetails']:
            ip = nodedetail['metadata']['ec2_ipaddress']

            if launch_request.hardwareprofile.nameFormat != '*':
                # Generate host name for spot instance
                fqdn = self.addHostApi.generate_node_name(
                    session,
                    launch_request.hardwareprofile.nameFormat,
                    dns_zone=launch_request.configDict['dns_domain'])
            else:
                fqdn = nodedetail['name']

            self._pre_add_host(
                fqdn,
                launch_request.hardwareprofile.name,
                launch_request.softwareprofile.name,
                ip)

            if 'metadata' in nodedetail and \
                    'ec2_instance_id' in nodedetail['metadata']:
                instance = self.__get_instance_by_instance_id(
                    launch_request.conn,
                    nodedetail['metadata']['ec2_instance_id'])

                if not instance:
                    self.getLogger().warning(
                        'Error inserting node [{0}]. AWS instance [{1}]'
                        ' does not exist'.format(
                            fqdn, nodedetail['metadata']['ec2_instance_id']))

                    continue

                self.getLogger().debug(
                    '__insert_nodes(): add node [{0}]'
                    ' instance: [{1}]'.format(
                        fqdn,
                        nodedetail['metadata']['ec2_instance_id']))
            else:
                instance = None

                self.getLogger().debug(
                    '__insert_nodes(): add node [{0}]'.format(fqdn))

            node = Node(name=fqdn)
            node.softwareprofile = launch_request.softwareprofile
            node.hardwareprofile = launch_request.hardwareprofile
            node.isIdle = False
            node.state = state.NODE_STATE_PROVISIONED
            node.addHostSession = self.addHostSession

            node.nics = [Nic(ip=ip, boot=True)]

            self.fire_provisioned_event(node)

            nodes.append(node)

            if instance:
                # Update instance cache
                node.instance = InstanceMapping(
                    instance=nodedetail['metadata']['ec2_instance_id']
                )

                # Add tags
                self.getLogger().debug(
                    'Assigning tags to instance [{0}]'.format(
                        instance.id))

                self.__assign_tags(
                    launch_request.configDict, launch_request.conn, node,
                    instance)

        return nodes

    def request_spot_instances(self,
                               dbSession: Session,
                               launch_request: LaunchRequest) -> List[Node]:
        """
        Make request for EC2 spot instances. Spot instance arguments are
        passed through 'addNodesRequest' in the dictionary
        'spot_instance_request.

        Minimally, 'price' needs to be specified. Sane defaults exist for all
        other values, similar to those used in the AWS Management Console.

        Raises:
            OperationFailed
        """

        addNodesRequest = launch_request.addNodesRequest
        cfgname = addNodesRequest['resource_adapter_configuration']
        dbHardwareProfile = launch_request.hardwareprofile
        dbSoftwareProfile = launch_request.softwareprofile

        configDict = launch_request.configDict

        conn = launch_request.conn

        self.getLogger().debug(
            'request_spot_instances(addNodeRequest=[%s], dbSession=[%s],'
            ' dbHardwareProfile=[%s], dbSoftwareProfile=[%s])' % (
                addNodesRequest, dbSession, dbHardwareProfile.name,
                dbSoftwareProfile.name))

        self._validate_ec2_launch_args(conn, configDict)

        security_group_ids: Union[List[str], None] = \
            self.__get_security_group_ids(configDict, conn)

        try:
            if configDict['use_instance_hostname']:
                nodes: List[Node] = []

                args = self.__get_request_spot_instance_args(
                    conn,
                    addNodesRequest,
                    configDict,
                    security_group_ids)

                resv = conn.request_spot_instances(
                    addNodesRequest['spot_instance_request']['price'],
                    configDict['ami'], **args)

                self.__post_add_spot_instance_request(resv,
                                                      dbHardwareProfile,
                                                      dbSoftwareProfile,
                                                      cfgname)
            else:
                nodes = self.__create_nodes(dbSession,
                                            configDict,
                                            dbHardwareProfile,
                                            dbSoftwareProfile,
                                            count=addNodesRequest['count'],
                                            initial_state='Allocated')

                with DbManager().session() as session:
                    for node in nodes:
                        args = self.__get_request_spot_instance_args(
                            conn,
                            addNodesRequest,
                            configDict,
                            security_group_ids,
                            node=node)

                        resv = conn.request_spot_instances(
                            addNodesRequest['spot_instance_request']['price'],
                            configDict['ami'], **args)

                        # Update instance cache
                        metadata = {
                            'spot_instance_request': resv[0].id,
                        }

                        adapter_cfg = self.load_resource_adapter_config(
                            session, cfgname
                        )

                        node.instance = InstanceMapping(
                            metadata=metadata,
                            resource_adapter_configuration=adapter_cfg
                        )

                        # Post 'add' message onto message queue
                        self.__post_add_spot_instance_request(resv,
                                                              dbHardwareProfile,
                                                              dbSoftwareProfile,
                                                              cfgname)

                    # this may be redundant...
                    session.commit()
        except boto.exception.EC2ResponseError as exc:
            raise OperationFailed(
                'Error requesting EC2 spot instances: {0} ({1})'.format(
                    exc.message, exc.error_code))
        except Exception as exc:  # pylint: disable=broad-except
            self.getLogger().exception(
                'Fatal error making spot instance request')

        return nodes

    def __get_request_spot_instance_args(self, conn: EC2Connection,
                                         addNodesRequest: dict,
                                         configDict: dict,
                                         security_group_ids: List[str],
                                         node: Optional[Node] = None):
        """
        Create dict of args for boto request_spot_instances() API
        """

        user_data = self.__get_user_data(configDict, node=node) \
            if configDict['cloud_init'] else None

        # Get common AWS launch args
        args = self.__get_common_launch_args(
            conn,
            configDict,
            security_group_ids=security_group_ids,
            user_data=user_data)

        args['count'] = 1 if node else addNodesRequest['count']

        if 'launch_group' in addNodesRequest:
            args['launch_group'] = addNodesRequest['launch_group']

        return args

    def __post_add_spot_instance_request(self, resv,
                                         dbHardwareProfile: HardwareProfile,
                                         dbSoftwareProfile: SoftwareProfile,
                                         cfgname: Union[str, None] = None) \
            -> None:
        # Send message to awsspotd (using zeromq)
        context = zmq.Context()

        try:
            socket = context.socket(zmq.REQ)
            socket.connect("tcp://localhost:5555")

            try:
                for r in resv:
                    request = {
                        'action': 'add',
                        'spot_instance_request_id': r.id,
                        'softwareprofile': dbSoftwareProfile.name,
                        'hardwareprofile': dbHardwareProfile.name,
                    }

                    if cfgname:
                        request['resource_adapter_configuration'] = \
                            cfgname

                    socket.send(json.dumps(request))

                    message = socket.recv()

                    self.getLogger().debug(
                        'request_spot_instances():'
                        ' response=[{0}]'.format(message))
            finally:
                socket.close()
        finally:
            context.term()

    def cancel_spot_instance_requests(self):
        """TODO"""

    def validate_start_arguments(self, addNodesRequest: Dict[str, Any],
                                 dbHardwareProfile: HardwareProfile,
                                 dbSoftwareProfile: SoftwareProfile) -> None: \
            # pylint: disable=unused-argument

        """
        Ensure arguments to start() instances are valid

        Raises:
            InvalidArgument
            ConfigurationError
        """

        cfgname = addNodesRequest.get('resource_adapter_configuration')
        if cfgname is None or cfgname == 'default':
            # use default resource adapter configuration, if set
            cfgname = dbHardwareProfile.default_resource_adapter_config.name \
                if dbHardwareProfile.default_resource_adapter_config else None

        configDict = self.getResourceAdapterConfig(cfgname)

        # Must specify number of nodes for EC2
        if 'count' not in addNodesRequest or addNodesRequest['count'] < 1:
            raise InvalidArgument('Invalid node count')

        if dbHardwareProfile.nameFormat != '*':
            if configDict['use_reverse_dns_hostname']:
                raise ConfigurationError(
                    '\'use_reverse_dns_hostname\' is enabled, but hardware'
                    ' profile does not allow setting host names. Set hardware'
                    ' profile name format to \'*\' and retry.')
            elif configDict['use_instance_hostname']:
                raise ConfigurationError(
                    '\'use_instance_hostname\' is enabled, but hardware'
                    ' profile does not allow setting host names.  Set'
                    ' hardware profile name format to \'*\' and retry.')
        else:
            if not configDict['use_instance_hostname']:
                raise ConfigurationError(
                    '\'use_instance_hostname\' is disabled, but hardware'
                    ' profile does not have a name format defined')

    def __add_idle_nodes(self, session: Session,
                         launch_request: LaunchRequest) -> List[Node]:
        """
        Create nodes in idle state
        """

        addNodesRequest = launch_request.addNodesRequest
        dbHardwareProfile = launch_request.hardwareprofile
        dbSoftwareProfile = launch_request.softwareprofile

        nodeCount = addNodesRequest['count']

        nodes = []

        for _ in range(nodeCount):
            addNodeRequest = {}

            addNodeRequest['addHostSession'] = self.addHostSession

            # Create a list of dicts containing the nic device name. One
            # entry for each nic defined in the hardware profile.

            addNodeRequest['nics'] = [
                {
                    'device': dbHardwareProfileNetwork.networkdevice.name,
                }
                for dbHardwareProfileNetwork in
                dbHardwareProfile.hardwareprofilenetworks
            ]

            # Create the node
            node = self.nodeApi.createNewNode(
                session, addNodeRequest, dbHardwareProfile,
                dbSoftwareProfile, validateIp=False)

            session.add(node)

            # Update instance cache
            node.instance = InstanceMapping(
                resource_adapter_configuration=self.load_resource_adapter_config(
                    session, addNodesRequest.get('resource_adapter_configuration')
                )
            )

            nodes.append(node)

            # Log node creation
            self.getLogger().debug('Created idle node [%s]' % (node.name))

        return nodes

    def _get_installer_ip(
            self, hardwareprofile: Optional[HardwareProfile] = None) -> str:
        if self.__installer_ip is None:
            if hardwareprofile and hardwareprofile.nics:
                self.__installer_ip = hardwareprofile.nics[0].ip
            else:
                self.__installer_ip = self.installer_public_ipaddress

        return self.__installer_ip

    def __get_common_user_data_settings(self, config: Dict[str, str],
                                        node: Optional[Node] = None) \
            -> Dict[str, str]:
        """
        Returns dict containing resource adapter configuration metadata
        """

        installerIp = config['installer_ip'] \
            if config['installer_ip'] else \
            self._get_installer_ip(
                hardwareprofile=node.hardwareprofile if node else None)

        dns_domain_value = '\'{0}\''.format(config['dns_domain']) \
            if config['dns_domain'] else None

        return {
            'installerHostName': self.installer_public_hostname,
            'installerIp': '\'{0}\''.format(installerIp)
                           if installerIp else 'None',
            'adminport': self._cm.getAdminPort(),
            'cfmuser': self._cm.getCfmUser(),
            'cfmpassword': self._cm.getCfmPassword(),
            'override_dns_domain': str(config['override_dns_domain']),
            'dns_options': '\'{0}\''.format(config['dns_options'])
                           if config['dns_options'] else None,
            'dns_domain': dns_domain_value,
            'dns_nameservers': _get_encoded_list(config['dns_nameservers']),
        }

    def __get_common_user_data_content(
            self, user_data_settings: Dict[str, str]) \
            -> str: # pylint: disable=no-self-use
        return """\
installerHostName = '%(installerHostName)s'
installerIpAddress = %(installerIp)s
port = %(adminport)d
cfmUser = '%(cfmuser)s'
cfmPassword = '%(cfmpassword)s'

# DNS resolution settings
override_dns_domain = %(override_dns_domain)s
dns_options = %(dns_options)s
dns_search = %(dns_domain)s
dns_domain = %(dns_domain)s
dns_nameservers = %(dns_nameservers)s
""" % (user_data_settings)

    def __get_user_data(self, config: Dict[str, str],
                        node: Optional[Node] = None) -> str:
        """
        Return metadata to be associated with each launched instance
        """

        if 'user_data_script_template' in config:
            with open(config['user_data_script_template']) as fp:
                return self.__get_user_data_script(fp, config, node=node)

        # process template file specified by 'cloud_init_script_template'
        # as YAML cloud-init configuration data
        return self.expand_cloud_init_user_data_template(config, node=node)

    def __get_user_data_script(self, fp: TextIO,
                               config: Dict[str, str],
                               node: Optional[Node] = None):
        settings_dict = self.__get_common_user_data_settings(config, node)

        result = ''

        for inp in fp.readlines():
            if inp.startswith('### SETTINGS'):
                result += self.__get_common_user_data_content(
                    settings_dict)
            else:
                result += inp

        if node and not config['use_instance_hostname']:
            # Use cloud-init to set fully-qualified domain name of instance
            cloud_init = """#cloud-config

fqdn: %s
""" % (node.name)

            combined_message = MIMEMultipart()

            sub_message = MIMEText(
                cloud_init, 'text/cloud-config', sys.getdefaultencoding())
            filename = 'user-data.txt'
            sub_message.add_header(
                'Content-Disposition',
                'attachment; filename="%s"' % (filename))
            combined_message.attach(sub_message)

            sub_message = MIMEText(
                result, 'text/x-shellscript', sys.getdefaultencoding())
            filename = 'bootstrap.py'
            sub_message.add_header(
                'Content-Disposition',
                'attachment; filename="%s"' % (filename))
            combined_message.attach(sub_message)

            return str(combined_message)

        # Fallback to default behaviour
        return result

    def __prelaunch_instances(self, dbSession: Session,
                              launch_request: LaunchRequest):
        """
        Launch EC2 instances prior to creating node records

        This method can only be used when the user metadata is same for
        all instances.
        """

        # log information about request
        self.__common_prelaunch(launch_request)

        user_data = self.__get_user_data(launch_request.configDict) \
            if launch_request.configDict['cloud_init'] else None

        security_group_ids: Union[List[str], None] = \
            self.__get_security_group_ids(
                launch_request.configDict, launch_request.conn)

        try:
            reservation = self.__launchEC2(
                launch_request.conn, launch_request.configDict,
                nodeCount=launch_request.addNodesRequest['count'],
                security_group_ids=security_group_ids,
                userData=user_data)
        except Exception as exc:
            # AWS error, unable to proceed
            self.getLogger().exception('AWS error launching instances')

            raise CommandFailed(str(exc))

        launch_request.node_request_queue = \
            [dict(instance=instance, status='launched')
             for instance in reservation.instances]

        # Wait for instances to reach 'running' state
        self.__wait_for_instances(dbSession, launch_request)

    def __add_hosts(self, dbSession: Session,
                    launch_request: LaunchRequest) -> None:
        """
        The "normal" add hosts workflow: create node records,
        launch one AWS instance for each node record, and map them.

        Raises:
            NetworkNotFound
        """

        conn = launch_request.conn
        configDict = launch_request.configDict
        addNodesRequest = launch_request.addNodesRequest
        dbHardwareProfile = launch_request.hardwareprofile
        dbSoftwareProfile = launch_request.softwareprofile

        count = addNodesRequest['count']

        self.getLogger().info(
            f'Preallocating {count} node(s) for mapping to AWS instances')

        nodes = self.__create_nodes(dbSession,
                                    configDict,
                                    dbHardwareProfile,
                                    dbSoftwareProfile,
                                    count=count)

        dbSession.add_all(nodes)
        dbSession.commit()

        launch_request.node_request_queue = init_node_request_queue(nodes)

        instances_launched = 0
        launch_exception = None

        resource_adapter_config = self.load_resource_adapter_config(
            dbSession,
            addNodesRequest.get('resource_adapter_configuration')
        )

        # log information about request
        self.__common_prelaunch(launch_request)

        security_group_ids: Union[List[str], None] = \
            self.__get_security_group_ids(configDict, conn)

        try:
            for node_request in launch_request.node_request_queue:
                userData = self.__get_user_data(
                    configDict, node=node_request['node']) \
                    if configDict['cloud_init'] else None

                # Launch instance
                try:
                    node_request['instance'] = self.__launchEC2(
                        conn, configDict,
                        security_group_ids=security_group_ids,
                        userData=userData).instances[0]

                    node_request['status'] = 'launched'

                    # Update instance cache as soon as instance launched

                    node_request['node'].instance = InstanceMapping(
                        instance=node_request['instance'].id,
                        resource_adapter_configuration=resource_adapter_config
                    )

                    # Increment launched instances counter
                    instances_launched += 1
                except CommandFailed as exc:
                    node_request['status'] = 'error'

                    self.getLogger().exception(
                        'Error launching AWS instance')

                    launch_exception = exc

                    # Halt processing of node request queue
                    break

            if instances_launched == 0:
                # Delete all failed node records
                self.__delete_failed_nodes(dbSession, launch_request)

                raise launch_exception

            # Wait on successfully launched instances
            self.__wait_for_instances(dbSession, launch_request)
        except Exception as exc:  # pylint: disable=broad-except
            if instances_launched == 0:
                raise

            self.getLogger().exception(
                'Exception while launching instances')

    def __delete_failed_nodes(self, dbSession: Session,
                              launch_request: LaunchRequest): \
            # pylint: disable=no-self-use
        for node_request in launch_request.node_request_queue:
            node = node_request['node']

            dbSession.delete(node)

    def __process_node_request_queue(self, dbSession: Session,
                                     launch_request: LaunchRequest) \
            -> List[Node]:
        """
        Iterate over all instances/nodes that have been started
        successfully. Clean up those that didn't start or timed out before
        reaching 'running' state.
        """

        count = launch_request.addNodesRequest['count']
        node_request_queue = launch_request.node_request_queue

        completed = 0

        # Iterate over all nodes in node request queue, cleaning up after
        # any that failed to launch
        for node_request in node_request_queue:
            if node_request['status'] == 'running':
                # Just count nodes in 'running' state
                completed += 1

                continue

            # clean up failed launches
            node = node_request.get('node')

            if not node:
                # instance launched, but no node record created
                continue

            # Ensure session node cache entry removed for failed launch
            AddHostServerLocal.clear_session_node(node)

            # finally, delete node record from database
            dbSession.delete(node)

        # Commit database transaction
        dbSession.commit()

        # Report if fewer than requested nodes launched
        if completed and completed < count:
            warnmsg = ('only %d of %d requested instances launched'
                       ' successfully' % (completed, count))

            self.getLogger().warning(warnmsg)

        return [node_request['node']
                for node_request in node_request_queue
                if node_request['status'] == 'running']

    def __aws_check_instance_state(self, instance):
        try:
            instance.update()
        except boto.exception.EC2ResponseError as exc:
            # Not even the sample boto code appears to handle this
            # scenario. It appears there's a race condition between
            # creating an instance and polling for the instance
            # status.
            # If the poll occurs before the instance has been
            # "registered" by the EC2 backend, it's possible the
            # update() call will raise a "not found" exception.
            # Subsequent update() calls are successful.

            self.getLogger().debug(
                'Ignoring exception raised while'
                ' updating instance: %s' % (str(exc)))

            return None

        return instance.state

    def process_item(self, launch_request: LaunchRequest, node_request: dict):
        """
        Raises:
            OperationFailed
            AWSOperationTimeoutError
        """

        max_sleep_time = 7000
        sleep_interval = 2000

        instance = node_request['instance']

        # Initially sleep for 10s prior to polling
        total_sleep_time = self.LAUNCH_INITIAL_SLEEP_TIME
        gevent.sleep(total_sleep_time)

        if self.__aws_check_instance_state(instance) == 'running':
            return

        for retries in itertools.count(1):
            temp = min(max_sleep_time, sleep_interval * 2 ** retries)

            sleeptime = (temp / 2 + random.randint(0, temp / 2)) / 1000.0

            self.getLogger().debug(
                'Sleeping %.2f seconds on instance [%s]' % (
                    sleeptime, instance.id))

            # Wait before polling instance state
            gevent.sleep(sleeptime)

            total_sleep_time += sleeptime

            state = self.__aws_check_instance_state(instance)

            if state == 'running':
                # Success! Instance reached running state.
                return

            if total_sleep_time >= launch_request.configDict['createtimeout']:
                raise AWSOperationTimeoutError(
                    'Timeout waiting for instance [{0}]'.format(instance.id))

            if instance.state != 'pending':
                # Instance in unexpected state, report error
                node_request['status'] = instance.state

                self.getLogger().error(
                    'Instance [%s] in unexpected state [%s]' % (
                        instance.state))

                raise OperationFailed(
                    'Error launching instance: state=[{0}]'.format(
                        instance.state))

    def __failed_launch_cleanup_handler(self, session: Session,
                                        node_request: dict) -> None:
        """
        Clean up routine Run when instance does not reach running state
        within create timeout period or reaches unexpected state.
        """

        self.getLogger().error(
            'Terminating failed instance [{0}]'.format(
                node_request['instance'].id))

        node = node_request['node'] if 'node' in node_request else None

        # this step may not be necessary but ensure instance isn't left
        # running if any transient condition caused the failure

        try:
            node_request['instance'].terminate()
        except boto.exception.EC2ResponseError as exc:
            self.getLogger().warning(
                'Error while terminating instance [{0}]: {1}'.format(
                    node_request['instance'].id, exc.message))

        if node:
            # Clean up instance cache
            session.delete(node.instance)

    def __wait_for_instance_coroutine(self, launch_request: LaunchRequest,
                                      dbSession: Session):
        """
        Process one node request from queue
        """

        configDict = launch_request.configDict

        while True:
            node_request = self.__launch_wait_queue.get()

            try:
                with gevent.Timeout(
                    configDict['launch_timeout'], TimeoutError):
                    self.process_item(launch_request, node_request)

                    self.getLogger().info(
                        'Instance [{0}] running'.format(
                            node_request['instance'].id))

                    # Instance launched successfully
                    self.__post_launch_action(
                        dbSession, launch_request, node_request)
            except Exception as exc:  # pylint: disable=broad-except
                # Instance launch failed
                if isinstance(exc, (AWSOperationTimeoutError, TimeoutError)):
                    logmsg = (
                        'Launch operation failed: timeout waiting for'
                        ' instance(s)')
                else:
                    logmsg = 'Instance launch failed: {0}'.format(str(exc))

                self.getLogger().error(logmsg)

                # Mark request as failed
                node_request['status'] = 'error'

                # Terminate instance
                self.__failed_launch_cleanup_handler(dbSession, node_request)
            finally:
                self.__launch_wait_queue.task_done()

    def __wait_for_instances(self, dbSession: Session,
                             launch_request: LaunchRequest) -> None:
        """
        Raises:
            ConfigurationError
            NicNotFound
        """

        self.getLogger().info(
            'Waiting for session [{0}] to complete...'.format(
                self.addHostSession))

        launch_requests = len(launch_request.node_request_queue)
        coroutine_count = 10 if launch_requests > 10 else launch_requests

        # Create coroutines
        for _ in range(coroutine_count):
            gevent.spawn(
                self.__wait_for_instance_coroutine, launch_request, dbSession)

        # Enqueue node requests
        for node_request in launch_request.node_request_queue:
            self.__launch_wait_queue.put(node_request)

        # Process queue
        self.__launch_wait_queue.join()

    def __post_launch_action(self, dbSession: Session,
                             launch_request: LaunchRequest,
                             node_request: dict) -> None:
        """
        Perform tasks after instance has been launched successfully

        Raises:
            AWSOperationTimeoutError
            ConfigurationError
        """

        instance = node_request['instance']

        if 'node' not in node_request:
            # create node record for instance

            self.getLogger().debug(
                'Creating node record for instance [{0}]'.format(
                    instance.id))

            # create Node record
            node = self.__create_nodes(dbSession,
                                       launch_request.configDict,
                                       launch_request.hardwareprofile,
                                       launch_request.softwareprofile)[0]

            dbSession.add(node)

            node_request['node'] = node
        else:
            node = node_request['node']

        primary_nic = get_primary_nic(node.nics)

        # Set IP for node
        primary_nic.ip = instance.private_ip_address

        if launch_request.configDict['use_instance_hostname']:
            # Update node name based on instance name assigned by AWS
            node.name = self.__get_node_name(launch_request, instance)

            resource_adapter_configuration = self.load_resource_adapter_config(
                dbSession,
                launch_request.addNodesRequest.get('resource_adapter_configuration')
            )

            node.instance = InstanceMapping(
                instance=instance.id,
                resource_adapter_configuration=resource_adapter_configuration,
            )

        # Commit node record changes (incl. host name and/or IP address)
        dbSession.commit()

        self._pre_add_host(
            node.name,
            node.hardwareprofile.name,
            node.softwareprofile.name,
            primary_nic.ip)

        # Assign instance tags
        self.getLogger().debug(
            'Assigning tags to instance [{0}]'.format(instance.id))

        total_sleep = 0

        while total_sleep < self.DEFAULT_CREATE_TIMEOUT:
            try:
                self.__assign_tags(
                    launch_request.configDict, launch_request.conn, node,
                    instance)

                break
            except boto.exception.EC2ResponseError as exc:
                self.getLogger().debug(
                    'Ignoring exception tagging instances: {0}'.format(
                        str(exc)))

            gevent.sleep(3)

            total_sleep += 3

        if total_sleep >= self.DEFAULT_CREATE_TIMEOUT:
            raise AWSOperationTimeoutError(
                'Timeout attempting to assign tags to instance {0}'.format(
                    instance.id))

        if total_sleep:
            self.getLogger().debug(
                'Waited %d seconds tagging instance %s' % (
                    total_sleep, instance.id))

        # This node is ready
        node_request['status'] = 'running'

        node.state = state.NODE_STATE_PROVISIONED

        self.fire_provisioned_event(node)

    def __assign_tags(self, configDict: dict, conn: EC2Connection,
                      node: Node, instance):
        """
        Add tags to instance and attached EBS volumes
        """

        if not configDict['use_tags']:
            return

        instance_specific_tags = {
            'tortuga:softwareprofile':
                node.softwareprofile.name,
            'tortuga:hardwareprofile':
                node.hardwareprofile.name,
            'tortuga:installer_hostname':
                self.installer_public_hostname,
            'tortuga:installer_ipaddress':
                configDict['installer_ip']
                if configDict['installer_ip'] else
                self.installer_public_ipaddress,
        }

        instance_specific_tags.update(configDict['tags'])

        if configDict['use_instance_hostname']:
            # Use default "Name" tag, if not defined in adapter
            # configuration
            if 'Name' not in configDict['tags']:
                instance_specific_tags['Name'] = 'Tortuga compute node'
        else:
            # Fallback to default behaviour
            instance_specific_tags['Name'] = node.name

        self.__addTags(conn, [instance.id], instance_specific_tags)

        # Volumes are tagged with user-defined tags only (not instance
        # specific resources)
        self.__tag_ebs_volumes(conn, configDict, instance)

    def __get_node_name(self, launch_request, instance):
        if launch_request.configDict['use_reverse_dns_hostname']:
            ip = instance.private_ip_address

            # use reverse DNS host name
            self.getLogger().debug(
                'Using reverse DNS lookup of IP [{}]'.format(ip))

            try:
                hostent = socket.gethostbyaddr(ip)

                return hostent[0]
            except socket.herror:
                name = instance.private_dns_name

                self.getLogger().debug(
                    'Error performing reverse lookup.'
                    ' Using AWS-assigned name: [{}]'.format(name))

                return name

        if launch_request.configDict['override_dns_domain']:
            hostname, _ = instance.private_dns_name.split('.', 1)

            # Use EC2-assigned host name with 'private_dns_zone'.
            return '{0}.{1}'.format(
                hostname, launch_request.configDict['dns_domain'])

        return instance.private_dns_name

    def __create_nodes(self, session: Session,
                       configDict: Dict[str, Any],
                       hardwareprofile: HardwareProfile,
                       softwareprofile: SoftwareProfile,
                       count: int = 1,
                       initial_state: Optional[str] = 'Launching') \
            -> List[Node]:
        """
        Creates new node object(s) with corresponding primary nic

        Raises:
            NetworkNotFound
        """

        nodes = []

        for _ in range(count):
            node = Node()

            # Generate the 'internal' host name
            if hardwareprofile.nameFormat != '*':
                # Generate node name
                node.name = self.addHostApi.generate_node_name(
                    session,
                    hardwareprofile.nameFormat,
                    dns_zone=configDict['dns_domain'])

            node.state = initial_state
            node.isIdle = False
            node.hardwareprofile = hardwareprofile
            node.softwareprofile = softwareprofile
            node.addHostSession = self.addHostSession

            # Create primary network interface
            node.nics.append(Nic(boot=True))

            nodes.append(node)

        return nodes

    def __parseEC2ResponseError(self, ex): \
            # pylint: disable=no-self-use
        """
        Helper method for parsing failed AWS API call
        """

        if ex.body:
            xmlDom = ET.fromstring(ex.body)

            msgElement = xmlDom.find('.//Message')

            if msgElement is not None:
                extErrMsg = msgElement.text
        else:
            extErrMsg = None

        return extErrMsg

    def __tag_ebs_volumes(self, conn, configDict, instance):
        # Get list of all EBS volumes associated with instance
        resource_ids = [
            bdm.volume_id
            for bdm in instance.block_device_mapping.values()
            if bdm.volume_id]

        # Add tags
        if resource_ids and 'tags' in configDict and configDict['tags']:
            self.__addTags(conn, resource_ids, configDict['tags'])

    def __get_security_group_by_name(self, conn, groupname): \
            # pylint: disable=no-self-use
        # For reasons unknown to me, Amazon will reject the request for
        # retrieving a VPC security group by name. This is why we iterate
        # over the list of all security groups to find the matching name.

        security_group = None

        for security_group in conn.get_all_security_groups():
            if security_group.name == groupname:
                break
        else:
            return None

        return security_group

    def _validate_ec2_launch_args(self, conn: EC2Connection,
                                  configDict: Dict[str, Any]):
        # # Get the kernel, if specified
        # if 'aki' in configDict and configDict['aki']:
        #     try:
        #         conn.get_all_kernels(configDict['aki'])
        #     except boto.exception.EC2ResponseError, ex:
        #         # Image isn't found, could be permission error or
        #         # non-existent error
        #         extErrMsg = self.__parseEC2ResponseError(ex)

        #         raise CommandFailed('Unable to access kernel [%s] (%s)' % (
        #             configDict['aki'], extErrMsg or '<no reason provided>'))

        # # Get the ramdisk, if specified
        # if 'ari' in configDict and configDict['ari']:
        #     try:
        #         conn.get_all_ramdisks(configDict['ari'])
        #     except boto.exception.EC2ResponseError, ex:
        #         # Image isn't found, could be permission error or
        #         # non-existent error

        #         extErrMsg = self.__parseEC2ResponseError(ex)

        #         raise CommandFailed(
        #             'Unable to access ramdisk [%s] (%s)' % (
        #                 configDict['ari'],
        #                 extErrMsg or '<no reason provided>'))

        # Create placement group if needed.
        if configDict['placementgroup']:
            try:
                self._logger.debug(
                    'Attempting to create placement group [%s]' % (
                        configDict['placementgroup']))

                conn.create_placement_group(configDict['placementgroup'])

                self._logger.debug(
                    'Created placement group [%s]' % (
                        configDict['placementgroup']))
            except boto.exception.EC2ResponseError as ex:
                # let this fail, group may already exist

                extErrMsg = self.__parseEC2ResponseError(ex)

                self._logger.warning(
                    'Unable to create placement group [%s] (%s)' % (
                        configDict['placementgroup'],
                        extErrMsg or '<no reason provided>'))

    def __get_common_launch_args(
            self, conn: EC2Connection, configDict: Dict[str, Any],
            security_group_ids: Optional[List[str]] = None,
            user_data: Optional[str] = None) -> Dict[str, Any]:
        """
        Return key-value pairs of arguments for passing to launch API
        """

        args = {
            'key_name': configDict['keypair'],
            'placement': configDict['zone'],
            'instance_type': configDict['instancetype'],
            'placement_group': configDict['placementgroup'],
        }

        if user_data:
            args['user_data'] = user_data

        if 'aki' in configDict and configDict['aki']:
            # Override kernel used for new instances
            args['kernel_id'] = configDict['aki']

        if 'ari' in configDict and configDict['ari']:
            # Override ramdisk used for new instances
            args['ramdisk_id'] = configDict['ari']

        # Build 'block_device_map'
        args['block_device_map'] = \
            self.__build_block_device_map(
                conn,
                configDict['block_device_map']
                if 'block_device_map' in configDict else None,
                configDict['ami'])

        if 'ebs_optimized' in configDict:
            args['ebs_optimized'] = configDict['ebs_optimized']

        if 'monitoring_enabled' in configDict:
            args['monitoring_enabled'] = configDict['monitoring_enabled']

        if 'iam_instance_profile_name' in configDict and \
                configDict['iam_instance_profile_name']:
            args['instance_profile_name'] = \
                configDict['iam_instance_profile_name']

        if 'subnet_id' in configDict and \
                configDict['subnet_id'] is not None:
            subnet_id = configDict['subnet_id']

            # If "subnet_id" is defined, we know the instance belongs to a
            # VPC. Handle the security group differently.
            primary_nic = NetworkInterfaceSpecification(
                subnet_id=subnet_id,
                groups=security_group_ids,
                associate_public_ip_address=configDict[
                    'associate_public_ip_address'],
            )

            args['network_interfaces'] = \
                NetworkInterfaceCollection(primary_nic)
        else:
            # Default instance (non-VPC)
            args['security_groups'] = configDict['securitygroup']

        return args

    def __launchEC2(self, conn: EC2Connection, configDict: dict,
                    nodeCount: int = 1,
                    security_group_ids: List[str] = None,
                    userData: str = None):
        """
        Launch one or more EC2 instances

        Raises:
            CommandFailed
        """

        self._validate_ec2_launch_args(conn, configDict)

        runArgs = self.__get_common_launch_args(
            conn,
            configDict, security_group_ids=security_group_ids,
            user_data=userData)

        runArgs['max_count'] = nodeCount

        try:
            return conn.run_instances(configDict['ami'], **runArgs)
        except boto.exception.EC2ResponseError as ex:
            extErrMsg = self.__parseEC2ResponseError(ex)

            # Pass the exception message through for status message
            # aesthetic purposes
            raise CommandFailed('AWS error: %s' % (extErrMsg))

    def __get_security_group_ids(self, configDict: dict,
                                 conn: EC2Connection) \
            -> Union[List[str], None]:
        """
        Convert list of security group names into list of security
        group ids. Returns None if VPC not being used.
        """

        if 'subnet_id' not in configDict or not configDict['subnet_id']:
            return None

        security_group_ids: List[str] = []

        for groupname in configDict['securitygroup'] or []:
            if groupname.startswith('sg-'):
                security_group_ids.append(groupname)

                continue

            # Look up security group by name
            security_group = self.__get_security_group_by_name(
                conn, groupname)

            if security_group is None:
                raise CommandFailed(
                    'Invalid security group [%s]' % (groupname))

            security_group_ids.append(security_group.id)

        return security_group_ids

    def __build_block_device_map(self, conn: EC2Connection,
                                 block_device_map, image_id: str):
        result = None

        if block_device_map:
            # Use block device mapping from adapter configuration
            self.getLogger().debug(
                'Setting \'block_device_map\' argument to [%s]' % (
                    block_device_map))

            result = block_device_map

        if not self.TEST_MODE:
            ami = conn.get_image(image_id)

            # determine root device name
            root_block_devices = ec2_get_root_block_devices(ami)

            if root_block_devices:
                root_block_device = root_block_devices[0]

                if not result or root_block_device not in iter(result.keys()):
                    # block device map previously undefined. Add entry for root
                    # device
                    if not result:
                        bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()

                        result = bdm
                    else:
                        bdm = result

                    # Add block device mapping entry for root disk
                    bdt = boto.ec2.blockdevicemapping.BlockDeviceType()
                    bdm[root_block_device] = bdt

                # Mark root block device for deletion on termination
                result[root_block_device].delete_on_termination = True
            else:
                self.getLogger().warning(
                    'Unable to determine root device name for'
                    ' AMI [%s]' % (ami.id))

                self.getLogger().warning(
                    'Delete on termination flag cannot be set')

            for device, bd in result.items():
                logmsg = 'BDM: device=[{0}], size=[{1}]'.format(
                    device, bd.size if bd.size else '<default>')

                if bd.ephemeral_name:
                    logmsg += ', ephemeral_name=[{0}]'.format(
                        bd.ephemeral_name)

                logmsg += ', delete_on_termination=[{0}]'.format(
                    bd.delete_on_termination)

                if bd.volume_type:
                    logmsg += ', volume_type=[{0}]'.format(bd.volume_type)

                self.getLogger().debug(logmsg)

        return result

    def stop(self, hardwareProfileName, deviceName):
        """
        Stops addhost daemon from creating additional nodes
        """

    def suspendActiveNode(self, node: Node) -> bool: \
            # pylint: disable=unused-argument
        return False

    def idleActiveNode(self, nodes: List[Node]) -> str:
        with DbManager().session() as session:
            for node in nodes:
                self.getLogger().info('Idling node [{0}]'.format(node.name))

                configDict = self.get_node_resource_adapter_config(node)

                if node.state != 'Discovered':
                    # Terminate instance
                    try:
                        conn = self.getEC2Connection(configDict)

                        conn.terminate_instances([node.instance.instance])
                    except boto.exception.EC2ResponseError as exc:
                        self.getLogger().warning(
                            'Error while terminating instance [{}]:'
                            ' {1}'.format(
                                node.instance.instance, exc.message
                            )
                        )

                    # Remove instance id from cache
                    session.delete(node.instance)

                # Unset IP address for node
                node.nics[0].ip = None

        return 'Discovered'

    def __addTags(self, conn: EC2Connection, resource_ids: List[str],
            keyvaluepairs: Dict[str, str]) -> None:
        """
        Create tags for resources
        """

        self.getLogger().debug('Adding tags to resources: {}'.format(
            ' '.join(resource_ids)))

        conn.create_tags(resource_ids, keyvaluepairs)

    def activateIdleNode(self, node: Node, softwareProfileName: str,
                         softwareProfileChanged: bool):
        self.getLogger().debug(
            'activateIdleNode(node=[%s],'
            ' softwareProfileName=[%s], softwareProfileChanged=[%s])' % (
                node.name, softwareProfileName, softwareProfileChanged))

        launch_request = LaunchRequest()

        launch_request.configDict = self.get_node_resource_adapter_config(node)

        launch_request.conn = self.getEC2Connection(launch_request.configDict)

        userData = self.__get_user_data(
            launch_request.configDict, node=node) \
            if launch_request.configDict['cloud_init'] else None

        launch_request.node_request_queue = init_node_request_queue([node])

        # log information about request
        self.__common_prelaunch(launch_request)

        security_group_ids: Union[List[str], None] = \
            self.__get_security_group_ids(
                launch_request.configDict, launch_request.conn)

        for node_request in launch_request.node_request_queue:
            # We now have the data needed to launch the instance
            node_request['instance'] = self.__launchEC2(
                launch_request.conn, launch_request.configDict,
                security_group_ids=security_group_ids,
                userData=userData).instances[0]

            node_request['status'] = 'launched'

            if not node.instance:
                node.instance = InstanceMapping()

            node.instance.instance = node_request['instance'].id

        # Wait for activated instance(s) to start
        with DbManager().session() as session:
            self.__wait_for_instances(session, launch_request)

    def __common_prelaunch(self, launch_request: LaunchRequest):
        """
        Write log entries about node launch request
        """

        count = launch_request.addNodesRequest['count']

        logmsg = 'Launching 1 instance' if count == 1 else \
            f'Launching {count} instances'

        self.getLogger().info(logmsg)

        if 'user_data_script_template' in launch_request.configDict:
            self.getLogger().info(
                'Using user-data script template [%s]' % (
                    launch_request.configDict['user_data_script_template']))
        elif 'cloud_init_script_template' in launch_request.configDict:
            self.getLogger().info(
                'Using cloud-init script template [%s]' % (
                    launch_request.configDict['cloud_init_script_template']))

        if 'securitygroup' not in launch_request.configDict or\
                not launch_request.configDict['securitygroup']:
            self.getLogger().warning(
                '\'securitygroup\' not configured. Default security group'
                ' will be used, which may not be desired behaviour'
            )

    def deleteNode(self, nodes: List[Node]) -> None:
        self.getLogger().debug(
            'Deleting nodes: [{}]'.format(
                ' '.join([node.name for node in nodes]))
        )
        with DbManager().session() as session:
            for node in nodes:
                if node.isIdle:
                    continue

                self.__delete_node(node)

            session.commit()

    def __delete_node(self, node: Node) -> None:
        """
        Terminate instance associated with node
        """

        if not node.instance or not node.instance.instance:
            # this really shouldn't ever happen. Nodes with backing AWS
            # instances should never not have an associated instance

            self.getLogger().warning(
                'Unable to determine AWS instance associated with'
                ' node [{0}]; instance may still be running!'.format(
                    node.name))

            return

        self.getLogger().info(
            'Terminating instance [{}] associated with node [{}]'.format(
                node.instance.instance, node.name
            )
        )

        # attempt to terminate by instance_id
        try:
            conn = self.getEC2Connection(
                self.get_node_resource_adapter_config(node))

            conn.terminate_instances([node.instance.instance])
        except boto.exception.EC2ResponseError as exc:
            self.getLogger().warning(
                'Error while terminating instance [{0}]: {1}'.format(
                    node.instance.instance, exc.message
                )
            )

    def transferNode(self, nodeIdSoftwareProfileTuples: Tuple[Node, str],
                     newSoftwareProfileName: str) -> None:
        """
        Transfer the given idle node
        """

        for node, oldSoftwareProfileName in nodeIdSoftwareProfileTuples:
            # Note call in log
            self.getLogger().debug(
                'transferNode (node=[%s])' % (node.name))

            # simply idle and activate
            self.idleActiveNode([node])

            self.activateIdleNode(
                node,
                newSoftwareProfileName,
                (newSoftwareProfileName != oldSoftwareProfileName))

    def migrateNode(self, node: Node, remainingNodeList: List[str],
                    liveMigrate: bool): \
            # pylint: disable=no-self-use,unused-argument
        raise TortugaException('EC2 nodes cannot be migrated')

    def runningOnEc2(self):
        """
        Determines if this node is running on EC2
        """

        if self.__runningOnEc2 is None:
            try:
                with open('/sys/devices/virtual/dmi/id/product_uuid') as fp:
                    buf = fp.read()

                self.__runningOnEc2 = buf.startswith('EC2')
            except IOError:
                self.__runningOnEc2 = False

        return self.__runningOnEc2

    def startupNode(self, nodes: List[Node],
                    remainingNodeList: Optional[List[str]] = None,
                    tmpBootMethod: Optional[str] = 'n'):
        """
        Start previously stopped instances
        """

        self.getLogger().debug(
            'startupNode(): dbNodes=[%s], remainingNodeList=[%s],'
            ' tmpBootMethod=[%s]' % (
                ' '.join([node.name for node in nodes]),
                ' '.join(remainingNodeList or []), tmpBootMethod))

        # Iterate over specified nodes
        for node in nodes:
            try:
                configDict = self.get_node_resource_adapter_config(node)

                conn = self.getEC2Connection(configDict)

                instance = self.__get_instance_by_instance_id(
                    conn,
                    node.instance.instance
                )
            except NodeNotFound:
                # Catch exception thrown if node's instance metadata is no
                # longer available.

                self.getLogger().warning(
                    'startupNode(): node [%s] has no corresponding AWS'
                    ' instance' % (node.name))

                continue

            try:
                if instance.state != 'running':
                    instance.start()

                    self.getLogger().info(
                        'Node [%s] (instance [%s]) started' % (
                            node.name, instance.id))
            except boto.exception.EC2ResponseError as exc:
                # Ignore any errors from EC2
                msg = 'Error starting node [%s] (instance [%s]): %s (%s)' % (
                    node.name, instance.id, exc.message, exc.error_code)

                self.getLogger().warning(msg)

                continue

            node.instance.instance = instance.id

    def getOptions(self, dbSoftwareProfile: SoftwareProfile,
                   dbHardwareProfile: HardwareProfile) -> dict: \
            # pylint: disable=unused-argument
        """
        Get settings for specified hardware profile
        """
        return {}

    def rebootNode(self, nodes: List[Node],
                   bSoftReset: Optional[bool] = False) -> None:
        self.getLogger().debug(
            'rebootNode(): nodes=[%s], soft=[%s]' % (
                ' '.join([node.name for node in nodes]), bSoftReset))

        for node in nodes:
            configDict = self.get_node_resource_adapter_config(node)

            conn = self.getEC2Connection(configDict)

            # Get EC2 instance
            try:
                instance = self.__get_instance_by_instance_id(
                    conn,
                    node.instance.instance
                )
            except ResourceNotFound:
                # Unable to get instance_id for unknown node
                self.getLogger().warning(
                    'rebootNode(): node [%s] has no associated'
                    ' instance' % (node.name))

                continue

            self.getLogger().debug(
                'rebootNode(): instance=[%s]' % (instance.id))

            try:
                instance.reboot()
            except boto.exception.EC2ResponseError as exc:
                # Ignore any errors from EC2
                msg = 'Error rebooting node [%s] (instance [%s]): %s (%s)' % (
                    node.name, instance.id, exc.message, exc.error_code)

                self.getLogger().warning(msg)

                continue

            self.getLogger().info(
                'Node [%s] (instance [%s]) rebooted' % (
                    node.name, instance.id))

    def shutdownNode(self, nodes: List[Node],
                     bSoftReset: Optional[bool] = False) -> None:
        self.getLogger().debug(
            'shutdownNode(): nodes=[%s], soft=[%s]' % (
                ' '.join([node.name for node in nodes]), bSoftReset))

        for node in nodes:
            configDict = self.get_node_resource_adapter_config(node)

            conn = self.getEC2Connection(configDict)

            # Get EC2 instance
            try:
                instance = self.__get_instance_by_instance_id(
                    conn,
                    node.instance.instance
                )
            except ResourceNotFound:
                # Unable to find instance for node
                continue

            self.getLogger().debug(
                'shutdownNode(): instance=[%s]' % (instance.id))

            try:
                instance.stop(force=not bSoftReset)

                self.getLogger().info(
                    'Node [%s] (instance [%s]) shutdown' % (
                        node.name, instance.id))
            except boto.exception.EC2ResponseError as exc:
                # Ignore any errors from EC2
                msg = ('Error shutting down node [%s] (instance [%s]):'
                       ' %s (%s)' % (
                           node.name, instance.id, exc.message,
                           exc.error_code))

                self.getLogger().warning(msg)

                continue

    def updateNode(self, session: Session, node: Node,
                   updateNodeRequest: dict) -> None: \
            # pylint: disable=unused-argument
        self.getLogger().debug(
            'updateNode(): node=[{0}]'.format(node.name))

        addNodesRequest = {}

        addNodesRequest['resource_adapter_configuration'] = \
            node.instance.resource_adapter_configuration.name

        if node.state == state.NODE_STATE_ALLOCATED and \
                'state' in updateNodeRequest and \
                updateNodeRequest['state'] != 'Allocated':
            # Node state transitioning from 'Allocated'

            self.getLogger().debug(
                'updateNode(): node [{0}] transitioning from [{1}]'
                ' to [{2}]'.format(
                    node.name, node.state, updateNodeRequest['state']))

            prov_nic = None

            for prov_nic in node.nics:
                if prov_nic.boot:
                    break

            if not prov_nic:
                prov_nic = node.nics[0]
                prov_nic.boot = True

            if prov_nic:
                self.getLogger().debug(
                    'updateNode(): node=[{0}] updating'
                    ' network'.format(node.name))

                self._pre_add_host(
                    node.name,
                    node.hardwareprofile.name,
                    node.softwareprofile.name,
                    prov_nic.ip)

        configDict = self.getResourceAdapterConfig(
            addNodesRequest['resource_adapter_configuration'])

        # Get connection to AWS
        conn = self.getEC2Connection(configDict)

        instance_id = updateNodeRequest['metadata']['ec2_instance_id']

        instance = self.__get_instance_by_instance_id(conn, instance_id)

        self.__assign_tags(configDict, conn, node, instance)

        node.instance = InstanceMapping(
            instance=instance_id,
            resource_adapter_configuration=self.load_resource_adapter_config(
                session,
                addNodesRequest.get('resource_adapter_configuration'))
        )

    def get_node_vcpus(self, name: str) -> int:
        """
        Return number of vcpus for node. Value of 'vcpus' configured
        in resource adapter configuration takes precedence over file
        lookup.

        Raises:
            NodeNotFound
            ResourceNotFound

        :param name: node name
        :return: number of vcpus
        :returntype: int

        """

        #
        # Default to zero, because if for some reason the node can't be found
        # (i.e. it was deleted in the background), then it will not be using
        # any cpus
        #
        vcpus = 0

        with DbManager().session() as session:
            try:
                configDict = self.get_node_resource_adapter_config(
                    NodesDbHandler().getNode(session, name)
                )

                vcpus = configDict.get('vcpus', 0)
                if not vcpus:
                    vcpus = self.get_instance_size_mapping(
                        configDict['instancetype'])

            except NodeNotFound:
                pass

        return vcpus

    def get_instance_size_mapping(self, value: str) -> int:
        """
        Use csv.DictReader() to parse CSV file from
        EC2Instances.info. The file "aws-instances.csv" is expected to be
        found in $TORTUGA_ROOT/config/aws-instances.csv

        :param value: AWS instance type
        :return: number of vcpus matching requesting instance type
        """
        vcpus = 1

        self.getLogger().debug(
            'get_instance_size_mapping(instancetype=[{0}])'.format(value))

        with open(os.path.join(self._cm.getKitConfigBase(),
                               'aws-instances.csv')) as fp:
            dr = csv.DictReader(fp)

            for entry in dr:
                if 'API Name' not in entry or 'vCPUs' not in entry:
                    # Skip possibility of malformed entry
                    continue

                if entry['API Name'] != value:
                    continue

                self.getLogger().debug(
                    'get_instance_size_mapping() cache hit')

                # Found matching entry
                vcpus = entry['vCPUs'].split(' ', 1)[0]

                break
            else:
                self.getLogger().debug(
                    'get_instance_size_mapping() cache miss')

        return vcpus


def get_primary_nic(nics: List[Nic]) -> Nic:
    result = [nic for nic in nics if nic.boot]

    if not result:
        raise NicNotFound('Provisioning nic not found')

    return result[0]

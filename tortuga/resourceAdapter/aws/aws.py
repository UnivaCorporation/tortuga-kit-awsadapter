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
import sys
import xml.etree.cElementTree as ET
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, NoReturn, Optional, Tuple, Union

import gevent
import gevent.queue
import zmq
from sqlalchemy.orm.session import Session

import boto
import boto.ec2
import boto.vpc
from boto.ec2.connection import EC2Connection
from boto.ec2.networkinterface import (NetworkInterfaceCollection,
                                       NetworkInterfaceSpecification)
from tortuga.addhost.addHostServerLocal import AddHostServerLocal
from tortuga.db.dbManager import DbManager
from tortuga.db.models.hardwareProfile import HardwareProfile
from tortuga.db.models.nic import Nic
from tortuga.db.models.node import Node
from tortuga.db.models.softwareProfile import SoftwareProfile
from tortuga.exceptions.commandFailed import CommandFailed
from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.exceptions.invalidArgument import InvalidArgument
from tortuga.exceptions.nicNotFound import NicNotFound
from tortuga.exceptions.nodeNotFound import NodeNotFound
from tortuga.exceptions.operationFailed import OperationFailed
from tortuga.exceptions.resourceNotFound import ResourceNotFound
from tortuga.exceptions.tortugaException import TortugaException
from tortuga.objects import resourceadapter_settings as settings
from tortuga.os_utility import osUtility
from tortuga.resourceAdapter.resourceAdapter import ResourceAdapter

from .awsHelpers import get_ec2_region
from .exceptions import AWSOperationTimeoutError
from .helpers import _get_encoded_list, ec2_get_root_block_devices
from .launchRequest import LaunchRequest, init_node_request_queue


class Aws(ResourceAdapter):
    """
    AWS resource adapter

    """
    __adaptername__ = 'aws'

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
        )
    }

    # Location of instance cache file
    DEFAULT_INSTANCE_CACHE_CONFIG_FILE = 'aws-instance.conf'

    # Default time in seconds before creates will return even if not
    # completed
    DEFAULT_CREATE_TIMEOUT = 900

    # Time (seconds) between attempts to update EC2 instance status to
    # avoid thrashing
    DEFAULT_SLEEP_TIME = 5

    def __init__(self, addHostSession: Optional[str] = None):
        super(Aws, self).__init__(addHostSession=addHostSession)

        # Initialize internal flags
        self.__runningOnEc2 = None
        self.__installer_ip = None

        self.__launch_wait_queue = gevent.queue.JoinableQueue()

    def getEC2Connection(self, configDict: dict) -> EC2Connection:
        connectionArgs = dict(
            aws_access_key_id=configDict['awsaccesskey'],
            aws_secret_access_key=configDict['awssecretkey'],
            region=configDict['region'])

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

        # Initialize EC2 connection
        return EC2Connection(**connectionArgs)

    def getResourceAdapterConfig(self, sectionName: Optional[str] = None):
        """
        Raises:
            ConfigurationError
        """

        # load default configuration
        configDict = self._loadConfigDict()

        if sectionName:
            overrideConfigDict = self._loadConfigDict(sectionName=sectionName)

            # 'user_data_script_template' and 'cloud_init_script_template'
            # are mutually exclusive arguments. Ensure resource adapter
            # configuration overrides default settings accordingly.

            if 'user_data_script_template' in overrideConfigDict and \
                    'cloud_init_script_template' in configDict:
                del configDict['cloud_init_script_template']

            if 'cloud_init_script_template' in overrideConfigDict and \
                    'user_data_script_template' in configDict:
                del configDict['user_data_script_template']

            configDict.update(overrideConfigDict)

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
        for key in ['keypair', 'instancetype', 'region',
                    'securitygroup', 'sleeptime', 'zone',
                    'placementgroup', 'endpoint',
                    'user_data_script_template', 'cloud_init',
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
                   ]:  # noqa
            config[key] = configDict[key] if key in configDict else None

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

        for key in ['aki', 'ari', 'proxy_host', 'proxy_port', 'proxy_user',
                    'proxy_pass',
                    'block_device_map']:
            if key in configDict:
                config[key] = configDict[key]

        config['region'] = get_ec2_region(
            config['awsaccesskey'] if 'awsaccesskey' in config else None,
            config['awssecretkey'] if 'awssecretkey' in config else None,
            region=config['region'] if 'region' in config else None)

        # Security group has to be a list
        if config['securitygroup']:
            vals = config['securitygroup'].split(',')

            config['securitygroup'] = [
                securitygroup.strip() for securitygroup in vals
            ]

        # Special handling for configuration options which aren't strings
        config['createtimeout'] = int(configDict['createtimeout']) \
            if 'createtimeout' in configDict else self.DEFAULT_CREATE_TIMEOUT

        config['sleeptime'] = int(configDict['sleeptime']) \
            if 'sleeptime' in configDict else self.DEFAULT_SLEEP_TIME

        config['monitoring_enabled'] = \
            configDict['monitoring_enabled'] \
            if 'monitoring_enabled' in configDict and \
            configDict['monitoring_enabled'].lower() == 'true' else False

        config['ebs_optimized'] = \
            configDict['ebs_optimized'] \
            if 'ebs_optimized' in configDict and \
            configDict['ebs_optimized'].lower() == 'true' else False

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
                    'Invalid \'cloud_init_script_template\''
                    'setting: {0}'.format(exc)
                )
        else:
            config['cloud_init'] = False

        if 'vpn' in configDict:
            raise ConfigurationError(
                'OpenVPN support is obsolete; remove \'vpn\' setting'
                ' from resource adapter configuration')

        # Support for instance tagging is enabled by default
        config['use_tags'] = configDict['use_tags'].lower() == 'true' \
            if 'use_tags' in configDict else True

        # 'use_instance_hostname' is enabled by default when Tortuga is
        # hosted on EC2.
        config['use_instance_hostname'] = \
            configDict['use_instance_hostname'].lower() == 'true' \
            if 'use_instance_hostname' in configDict else True

        # Parse out user-defined tags
        config['tags'] = {}

        if 'tags' in configDict and configDict['tags']:
            # Support tag names/values containing spaces and tags without a
            # value.
            for tagdef in shlex.split(configDict['tags']):
                key, value = tagdef.rsplit('=', 1) \
                    if '=' in tagdef else (tagdef, '')

                config['tags'][key] = value

        if 'block_device_map' in configDict:
            config['block_device_map'] = self.__process_block_device_map(
                configDict['block_device_map'])

        # Convert 'associate_public_ip_address' to bool
        config['associate_public_ip_address'] = \
            config['associate_public_ip_address'].lower() == 'true' \
            if config['associate_public_ip_address'] is not None else None

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
                config['dns_domain'] = config['dns_domain'] \
                    if 'dns_domain' in config and config['dns_domain'] else \
                    self.private_dns_zone

            config['dns_nameservers'] = config['dns_nameservers'].split(' ') \
                if config['dns_nameservers'] else []

            if not config['dns_nameservers']:
                # Ensure 'dns_nameservers' defaults to the Tortuga installer
                # as the DNS nameserver
                config['dns_nameservers'].append(
                    self.installer_public_ipaddress)

        del config['dns_search']

        # Attempt to use DNS setting from DHCP Option Set associated with VPC
        if config['subnet_id'] and config['override_dns_domain'] and not \
                config['dns_domain']:
            # Attempt to look up default DNS domain from DHCP options set
            domain = self.__get_vpc_default_domain(config)
            if domain:
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
            vpcconn = boto.vpc.VPCConnection(
                aws_access_key_id=config['awsaccesskey'],
                aws_secret_access_key=config['awssecretkey'],
                region=config['region'])
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
                          default: Optional[Union[bool, None]] = None) -> bool: \
            # pylint: disable=no-self-use
        return value.lower().startswith('t') \
            if value is not None else default

    def __process_block_device_map(self, cfg_block_device_map: str) -> boto.ec2.blockdevicemapping.BlockDeviceMapping:
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

    def __instanceCacheGet(self, conn: EC2Connection, node: Node):
        """
        Retrieves the instance associated with a node out of
        the cache

        Raises:
            ResourceNotFound
        """

        config = self.instanceCacheGet(node.name)

        if 'instance' not in config:
            self.getLogger().debug(
                'Cache miss: node [%s], no instance' % (node.name))

            return None

        instance_id = config['instance']

        self.getLogger().debug(
            'Cache hit: node [%s], instance [%s]' % (
                node.name, instance_id))

        instance = self.__get_instance_by_instance_id(conn, instance_id)

        if not instance:
            # We couldn't find the instance we wanted
            self.getLogger().error(
                'Cache error: node [%s], instance [%s], not found'
                ' in EC2' % (node.name, instance_id))

        return instance

    def __get_instance_by_instance_id(self, conn: EC2Connection,
                                      instance_id: str): \
            # pylint: disable=no-self-use
        # Find the instance itself
        reservations = [r for r in conn.get_all_reservations(
            filters={'instance-id': instance_id})]

        if not reservations:
            return None

        return reservations[0].instances[0]

    def start(self, addNodesRequest: dict, dbSession: Session,
              dbHardwareProfile: HardwareProfile,
              dbSoftwareProfile: Optional[Union[SoftwareProfile, None]] = None) -> List[Node]:
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

        if 'spot_instance_request' in addNodesRequest:
            nodes = self.request_spot_instances(
                addNodesRequest, dbSession, dbHardwareProfile,
                dbSoftwareProfile)

            return nodes

        cfgname = addNodesRequest['resource_adapter_configuration'] \
            if 'resource_adapter_configuration' in addNodesRequest else \
            None

        # If the resource adapter configuration profile is specified and that
        # profile does not exist, getResourceAdapterConfig() raises an
        # exception

        configDict = self.getResourceAdapterConfig(cfgname)

        # Get connection to AWS
        conn = self.getEC2Connection(configDict)

        launch_request = LaunchRequest()
        launch_request.hardwareprofile = dbHardwareProfile
        launch_request.softwareprofile = dbSoftwareProfile
        launch_request.addNodesRequest = addNodesRequest
        launch_request.conn = conn
        launch_request.configDict = configDict

        if 'nodeDetails' in addNodesRequest and \
                addNodesRequest['nodeDetails']:
            if 'metadata' in addNodesRequest['nodeDetails'][0] and \
                    'ec2_instance_id' in \
                    addNodesRequest['nodeDetails'][0]['metadata']:
                return self.__insert_nodes(dbSession, launch_request)

        if dbSoftwareProfile is None or dbSoftwareProfile.isIdle:
            # Add idle nodes
            nodes = self.__add_idle_nodes(dbSession, launch_request)
        else:
            # Add (active) nodes
            if configDict['use_instance_hostname']:
                # Create instances before node records. We need to the
                # instance to exist to get the host name for the node
                # record.
                self.__prelaunch_instances(dbSession, launch_request)
            else:
                # Create node records before instances
                self.__add_hosts(dbSession, launch_request)

            nodes = self.__process_node_request_queue(
                dbSession, launch_request)

        # This is a necessary evil for the time being, until there's
        # a proper context manager implemented.
        self.addHostApi.clear_session_nodes(nodes)

        return nodes

    def __insert_nodes(self, session: Session,
                       launch_request: LaunchRequest): \
            # pylint: disable=unused-argument
        """
        Directly insert nodes with pre-existing AWS instances

        This is primarily used for supporting spot instances where an
        AWS instance exists before the Tortuga associated node record.
        """

        self.getLogger().debug('__insert_nodes()')

        nodes = []

        for nodedetail in launch_request.addNodesRequest['nodeDetails']:
            ip = nodedetail['metadata']['ec2_ipaddress']

            if launch_request.hardwareprofile.nameFormat != '*':
                # Generate host name for spot instance
                fqdn = self.addHostApi.generate_node_name(
                    launch_request.hardwareprofile.nameFormat,
                    dns_zone=self.private_dns_zone)
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
            node.state = 'Provisioned'
            node.addHostSession = self.addHostSession

            node.nics = [Nic(ip=ip, boot=True)]

            nodes.append(node)

            if instance:
                # Update instance cache
                self.instanceCacheSet(
                    node.name,
                    launch_request.addNodesRequest,
                    instance_id=nodedetail['metadata']['ec2_instance_id'])

                # Add tags
                self.getLogger().debug(
                    'Assigning tags to instance [{0}]'.format(
                        instance.id))

                self.__assign_tags(
                    launch_request.configDict, launch_request.conn, node,
                    instance)

        return nodes

    def instanceCacheSet(self, name: str, addNodesRequest: dict,
                         instance_id: Optional[Union[str, None]] = None,
                         metadata: Optional[Union[dict, None]] = None):
        """
        Overriden AWS-specific instance cache update implementation

        'instance_id' may be None when adding idle nodes.

        'metadata' allows merging existing metadata into the instance cache.
        """

        new_metadata = dict(list(metadata.items())) if metadata else {}

        if instance_id:
            new_metadata['instance'] = instance_id

        if 'resource_adapter_configuration' in addNodesRequest and \
                addNodesRequest['resource_adapter_configuration'] != \
                'default':
            # So we don't write a file full of "defaults", do not write
            # adapter configuration profile 'default'

            new_metadata['resource_adapter_configuration'] = \
                addNodesRequest['resource_adapter_configuration']

        super(Aws, self).instanceCacheSet(name, metadata=new_metadata)

    def request_spot_instances(self, addNodesRequest: dict,
                               dbSession: Session,
                               dbHardwareProfile: HardwareProfile,
                               dbSoftwareProfile: SoftwareProfile) -> List[Node]:
        """
        Make request for EC2 spot instances. Spot instance arguments are
        passed through 'addNodesRequest' in the dictionary
        'spot_instance_request.

        Minimally, 'price' needs to be specified. Sane defaults exist for all
        other values, similar to those used in the AWS Management Console.

        Raises:
            OperationFailed
        """

        self.getLogger().debug(
            'request_spot_instances(addNodeRequest=[%s], dbSession=[%s],'
            ' dbHardwareProfile=[%s], dbSoftwareProfile=[%s])' % (
                addNodesRequest, dbSession, dbHardwareProfile.name,
                dbSoftwareProfile.name))

        cfgname = addNodesRequest['resource_adapter_configuration'] \
            if 'resource_adapter_configuration' in addNodesRequest else \
            None

        configDict = self.getResourceAdapterConfig(cfgname)

        # Get connection to AWS
        conn = self.getEC2Connection(configDict)

        ami = self._validate_ec2_launch_args(conn, configDict)

        security_group_ids: Union[List[str], None] = \
            self.__get_security_group_ids(configDict, conn)

        try:
            if configDict['use_instance_hostname']:
                nodes = []

                args = self.__get_request_spot_instance_args(
                    addNodesRequest,
                    configDict,
                    ami,
                    security_group_ids)

                resv = conn.request_spot_instances(
                    addNodesRequest['spot_instance_request']['price'],
                    configDict['ami'], **args)

                self.__post_add_spot_instance_request(resv,
                                                      dbHardwareProfile,
                                                      dbSoftwareProfile,
                                                      cfgname)
            else:
                nodes = self.__createNodes(addNodesRequest['count'],
                                           dbHardwareProfile,
                                           dbSoftwareProfile,
                                           initial_state='Allocated')

                for node in nodes:
                    args = self.__get_request_spot_instance_args(
                        addNodesRequest,
                        configDict,
                        ami,
                        security_group_ids,
                        node=node)

                    resv = conn.request_spot_instances(
                        addNodesRequest['spot_instance_request']['price'],
                        configDict['ami'], **args)

                    # Update instance cache
                    metadata = {
                        'spot_instance_request': resv[0].id,
                    }

                    if cfgname:
                        metadata['resource_adapter_configuration'] = cfgname

                    self.instanceCacheSet(
                        node.name, addNodesRequest, metadata=metadata)

                    # Post 'add' message onto message queue
                    self.__post_add_spot_instance_request(resv,
                                                          dbHardwareProfile,
                                                          dbSoftwareProfile,
                                                          cfgname)
        except boto.exception.EC2ResponseError as exc:
            raise OperationFailed(
                'Error requesting EC2 spot instances: {0} ({1})'.format(
                    exc.message, exc.error_code))
        except Exception as exc:
            self.getLogger().exception(
                'Fatal error making spot instance request')

        return nodes

    def __get_request_spot_instance_args(self, addNodesRequest: dict,
                                         configDict: dict,
                                         ami: str,
                                         security_group_ids: List[str],
                                         node: Optional[Union[Node, None]] = None):
        """
        Create dict of args for boto request_spot_instances() API
        """

        user_data = self.__get_user_data(configDict, node=node)

        # Get common AWS launch args
        args = self.__get_common_launch_args(
            configDict,
            ami,
            security_group_ids=security_group_ids,
            user_data=user_data)

        args['count'] = 1 if node else addNodesRequest['count']

        if 'launch_group' in addNodesRequest:
            args['launch_group'] = addNodesRequest['launch_group']

        return args

    def __post_add_spot_instance_request(self, resv,
                                         dbHardwareProfile: HardwareProfile,
                                         dbSoftwareProfile: SoftwareProfile,
                                         cfgname: Optional[str] = None) -> NoReturn:
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

    def validate_start_arguments(self, addNodesRequest: dict,
                                 dbHardwareProfile: HardwareProfile,
                                 dbSoftwareProfile: SoftwareProfile) -> NoReturn: \
            # pylint: disable=unused-argument

        """
        Ensure arguments to start() instances are valid

        Raises:
            InvalidArgument
            ConfigurationError
        """

        cfgname = addNodesRequest['resource_adapter_configuration'] \
            if 'resource_adapter_configuration' in addNodesRequest else \
            None

        configDict = self.getResourceAdapterConfig(cfgname)

        # Must specify number of nodes for EC2
        if 'count' not in addNodesRequest or addNodesRequest['count'] < 1:
            raise InvalidArgument('Invalid node count')

        if configDict['use_instance_hostname']:
            if dbHardwareProfile.nameFormat != '*':
                raise ConfigurationError(
                    '\'use_instance_hostname\' is enabled, but hardware'
                    ' profile does not allow setting host names.  Set'
                    ' hardware profile name format to \'*\' and retry.')
        else:
            if dbHardwareProfile.nameFormat == '*':
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
            self.instanceCacheSet(node.name, addNodesRequest)

            nodes.append(node)

            # Log node creation
            self.getLogger().debug('Created idle node [%s]' % (node.name))

        return nodes

    def _get_installer_ip(self, hardwareprofile: Optional[Union[HardwareProfile, None]] = None) -> str:
        if self.__installer_ip is None:
            if hardwareprofile and hardwareprofile.nics:
                self.__installer_ip = hardwareprofile.nics[0].ip
            else:
                self.__installer_ip = self.installer_public_ipaddress

        return self.__installer_ip

    def __get_common_user_data_settings(self, configDict: dict,
                                        node: Optional[Union[Node, None]] = None):
        installerIp = self._get_installer_ip(
            hardwareprofile=node.hardwareprofile if node else None)

        dns_domain_value = '\'{0}\''.format(configDict['dns_domain']) \
            if configDict['dns_domain'] else None

        settings_dict = {
            'installerHostName': self.installer_public_hostname,
            'installerIp': '\'{0}\''.format(installerIp)
                           if installerIp else 'None',
            'adminport': self._cm.getAdminPort(),
            'cfmuser': self._cm.getCfmUser(),
            'cfmpassword': self._cm.getCfmPassword(),
            'override_dns_domain': str(configDict['override_dns_domain']),
            'dns_options': '\'{0}\''.format(configDict['dns_options'])
                           if configDict['dns_options'] else None,
            'dns_domain': dns_domain_value,
            'dns_nameservers': _get_encoded_list(
                configDict['dns_nameservers']),
        }

        return settings_dict

    def __get_common_user_data_content(self, settings_dict: dict) -> str: \
            # pylint: disable=no-self-use
        result = """\
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
""" % (settings_dict)

        return result

    def __get_user_data(self, configDict: dict,
                        node: Optional[Union[Node, None]] = None):
        if not configDict['cloud_init']:
            return None

        if 'user_data_script_template' in configDict:
            return self.__get_user_data_script(configDict, node=node)

        # process template file specified by 'cloud_init_script_template'
        # as YAML cloud-init configuration data
        return self.expand_cloud_init_user_data_template(configDict, node=node)

    def __get_user_data_script(self, configDict: dict,
                               node: Optional[Union[Node, None]] = None):
        self.getLogger().info(
            'Using user-data script template [%s]' % (
                configDict['user_data_script_template']))

        settings_dict = \
            self.__get_common_user_data_settings(configDict, node)

        with open(configDict['user_data_script_template']) as fp:
            result = ''

            for inp in fp.readlines():
                if inp.startswith('### SETTINGS'):
                    result += self.__get_common_user_data_content(
                        settings_dict)
                else:
                    result += inp

        combined_message = MIMEMultipart()

        if node and not configDict['use_instance_hostname']:
            # Use cloud-init to set fully-qualified domain name of instance
            cloud_init = """#cloud-config

fqdn: %s
""" % (node.name)

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

        user_data = self.__get_user_data(launch_request.configDict)

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
                    launch_request: LaunchRequest):
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
            'Preallocating %d node(s) for mapping to AWS instances' % (
                count))

        nodes = self.__createNodes(
            addNodesRequest['count'], dbHardwareProfile, dbSoftwareProfile)

        dbSession.add_all(nodes)
        dbSession.commit()

        launch_request.node_request_queue = init_node_request_queue(nodes)

        instances_launched = 0
        launch_exception = None

        security_group_ids: Union[List[str], None] = \
            self.__get_security_group_ids(configDict, conn)

        try:
            for node_request in launch_request.node_request_queue:
                userData = self.__get_user_data(
                    configDict, node=node_request['node'])

                # Launch instance
                try:
                    node_request['instance'] = self.__launchEC2(
                        conn, configDict,
                        security_group_ids=security_group_ids,
                        userData=userData).instances[0]

                    node_request['status'] = 'launched'

                    # Update instance cache as soon as instance launched
                    self.instanceCacheSet(
                        node_request['node'].name,
                        addNodesRequest,
                        instance_id=node_request['instance'].id)

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
        except Exception as exc:
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
                                     launch_request: LaunchRequest) -> List[Node]:
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
        total_sleep_time = 10.0
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

    def __failed_launch_cleanup_handler(self, node_request: dict) -> NoReturn:
        """
        Clean up routine Run when instance does not reach running state
        within create timeout period or reaches unexpected state.
        """

        self.getLogger().error(
            'Cleaning up failed instance [{0}]'.format(
                node_request['instance'].id))

        node = node_request['node'] if 'node' in node_request else None

        self.__terminate_instance(node_request['instance'])

        if node:
            # Clean up instance cache
            self.instanceCacheDelete(node.name)

    def __wait_for_instance_coroutine(self, launch_request: LaunchRequest,
                                      dbSession: Session):
        """
        Process one node request from queue
        """

        while True:
            node_request = self.__launch_wait_queue.get()

            try:
                self.process_item(launch_request, node_request)

                self.getLogger().info(
                    'Instance [{0}] running'.format(
                        node_request['instance'].id))

                # Instance launched successfully
                self.__post_launch_action(
                    dbSession, launch_request, node_request)
            except (AWSOperationTimeoutError, Exception) as exc:
                # Instance launch failed
                if isinstance(exc, AWSOperationTimeoutError):
                    logmsg = (
                        'Launch operation failed: timeout waiting for'
                        ' instance(s)')
                else:
                    logmsg = 'Instance launch failed: {0}'.format(str(exc))

                self.getLogger().error(logmsg)

                # Mark request as failed
                node_request['status'] = 'error'

                # Terminate instance
                self.__failed_launch_cleanup_handler(node_request)
            finally:
                self.__launch_wait_queue.task_done()

    def __wait_for_instances(self, dbSession: Session,
                             launch_request: LaunchRequest) -> NoReturn:
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
                             launch_request: dict,
                             node_request: LaunchRequest) -> NoReturn:
        """
        Perform tasks after instance has been launched successfully

        Raises:
            AWSOperationTimeoutError
            ConfigurationError
        """

        if 'node' not in node_request:
            self.getLogger().debug(
                'Creating node record for instance [{0}]'.format(
                    node_request['instance'].id))

            node_request['node'] = self.__initialize_node(
                launch_request.hardwareprofile,
                launch_request.softwareprofile)

            dbSession.add(node_request['node'])

        node = node_request['node']

        instance = node_request['instance']

        primary_nic = get_primary_nic(node.nics)

        # Set IP for node
        primary_nic.ip = instance.private_ip_address

        if launch_request.configDict['use_instance_hostname']:
            # Update node name based on instance name assigned by AWS
            node.name = self.__get_node_name(launch_request, instance)

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

        node.state = 'Provisioned'

    def __assign_tags(self, configDict: dict, conn: EC2Connection,
                      node: Node, instance):
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
                self.installer_public_ipaddress,
        }

        if configDict['use_instance_hostname']:
            # Use default "Name" tag, if not defined in adapter
            # configuration
            if 'Name' not in configDict['tags']:
                instance_specific_tags['Name'] = 'Tortuga compute node'
        else:
            # Fallback to default behaviour
            instance_specific_tags['Name'] = node.name

        self.__addTags(
            conn, [instance.id],
            dict(list(configDict['tags'].items()) +
                 list(instance_specific_tags.items())))

        # Volumes are tagged with user-defined tags only (not instance
        # specific resources)
        self.__tag_ebs_volumes(conn, configDict, instance)

    def __get_node_name(self, launch_request, instance):
        if launch_request.configDict['override_dns_domain']:
            hostname, _ = instance.private_dns_name.split('.', 1)

            # Use EC2-assigned host name with 'private_dns_zone'.
            fqdn = '{0}.{1}'.format(
                hostname, launch_request.configDict['dns_domain'])
        else:
            fqdn = instance.private_dns_name

        # Update instance cache
        self.instanceCacheSet(
            fqdn,
            launch_request.addNodesRequest,
            instance_id=instance.id)

        return fqdn

    def __createNodes(self, count: int, hardwareprofile: HardwareProfile,
                      softwareprofile: SoftwareProfile,
                      initial_state: Optional[str] = 'Launching'):
        """
        Bulk node creation

        Raises:
            NetworkNotFound
        """

        return [self.__initialize_node(
            hardwareprofile, softwareprofile, initial_state=initial_state)
                for _ in range(count)]

    def __initialize_node(self, hardwareprofile: HardwareProfile,
                          softwareprofile: SoftwareProfile,
                          initial_state: Optional[str] = 'Launching'):
        node = Node()

        # Generate the 'internal' host name
        if hardwareprofile.nameFormat != '*':
            # Generate node name
            node.name = self.addHostApi.generate_node_name(
                hardwareprofile.nameFormat,
                dns_zone=self.private_dns_zone)

        node.state = initial_state
        node.isIdle = False
        node.hardwareprofile = hardwareprofile
        node.softwareprofile = softwareprofile
        node.addHostSession = self.addHostSession

        # Create primary network interface
        node.nics.append(Nic(boot=True))

        return node

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
                                  configDict: dict):
        # Get the image
        try:
            imageList = conn.get_all_images(configDict['ami'])
        except boto.exception.EC2ResponseError as ex:
            # Image isn't found, could be permission error or
            # non-existent error

            extErrMsg = self.__parseEC2ResponseError(ex)

            raise CommandFailed('Error accessing AMI [%s] (%s)' % (
                configDict['ami'], extErrMsg or '<no reason provided>'))

        ami = imageList[0]

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

        return ami

    def __get_common_launch_args(self, configDict, ami,
                                 security_group_ids=None, user_data=None):
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
                configDict['block_device_map']
                if 'block_device_map' in configDict else None, ami)

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
                    nodeCount: Optional[int] = 1,
                    security_group_ids=None, userData=None):
        """
        Launch one or more EC2 instances

        Raises:
            CommandFailed
        """

        self.getLogger().debug(
            '__launchEC2(): nodeCount=[%s]' % (nodeCount))

        ami = self._validate_ec2_launch_args(conn, configDict)

        runArgs = self.__get_common_launch_args(
            configDict, ami, security_group_ids=security_group_ids,
            user_data=userData)

        runArgs['max_count'] = nodeCount

        self.getLogger().info('Launching %d AWS %s' % (
            nodeCount, 'instances' if nodeCount > 1 else 'instance'))

        try:
            return conn.run_instances(ami.id, **runArgs)
        except boto.exception.EC2ResponseError as ex:
            extErrMsg = self.__parseEC2ResponseError(ex)

            # Pass the exception message through for status message
            # aesthetic purposes
            raise CommandFailed('AWS error: %s' % (extErrMsg))

    def __get_security_group_ids(self, configDict: dict,
                                 conn: EC2Connection) -> Union[List[str], None]:
        """
        Convert list of security group names into list of security
        group ids. Returns None if VPC not being used.
        """

        if 'subnet_id' not in configDict or not configDict['subnet_id']:
            return None

        security_group_ids: List[str] = []

        if 'securitygroup' not in configDict or \
                not configDict['securitygroup']:
            raise CommandFailed(
                'AWS security group not defined. Check AWS'
                ' configuration.')

        for groupname in configDict['securitygroup']:
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

    def __build_block_device_map(self, block_device_map, ami):
        result = None

        if block_device_map:
            # Use block device mapping from adapter configuration
            self.getLogger().debug(
                'Setting \'block_device_map\' argument to [%s]' % (
                    block_device_map))

            result = block_device_map

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

    def __simple_get_instance_by_node(self, conn, node):
        # Get EC2 instance and terminate it
        try:
            return self.__instanceCacheGet(conn, node)
        except ResourceNotFound:
            # Node not found in instance cache
            self.getLogger().warning(
                'No associated AWS instance found for node [%s]' % (node.name))

        return None

    def idleActiveNode(self, nodes: List[Node]) -> str:
        for node in nodes:
            self.getLogger().info('Idling node [{0}]'.format(node.name))

            configDict = self.getResourceAdapterConfig(
                self.getResourceAdapterConfigProfileByNodeName(node.name))

            if node.state != 'Discovered':
                # Terminate instance
                instance = self.__simple_get_instance_by_node(
                    self.getEC2Connection(configDict), node)

                if instance:
                    self.__terminate_instance(instance)

                    # Remove instance id from cache
                    self.instanceCacheUpdate(node.name, deleted=['instance'])

            # Unset IP address for node
            node.nics[0].ip = None

        return 'Discovered'

    def __addTags(self, conn, resource_ids, keyvaluepairs):
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

        launch_request.configDict = \
            self.getResourceAdapterConfig(
                self.getResourceAdapterConfigProfileByNodeName(node.name))

        launch_request.conn = self.getEC2Connection(launch_request.configDict)

        userData = self.__get_user_data(launch_request.configDict, node=node)

        launch_request.node_request_queue = init_node_request_queue([node])

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

            self.instanceCacheUpdate(
                node_request['node'].name,
                added=[('instance', node_request['instance'].id)])

        # Wait for activated instance(s) to start
        with DbManager().session() as session:
            self.__wait_for_instances(session, launch_request)

    def deleteNode(self, nodes: List[Node]) -> NoReturn:
        for node in nodes:
            self.__delete_node(node)

        self.getLogger().info('%d node(s) deleted' % (len(nodes)))

    def __delete_node(self, node: Node) -> NoReturn:
        self.getLogger().info('Deleting node [{0}]'.format(node.name))

        try:
            configDict = self.getResourceAdapterConfig(
                self.getResourceAdapterConfigProfileByNodeName(node.name))

            # Remove Puppet certificate
            bhm = osUtility.getOsObjectFactory().getOsBootHostManager()
            bhm.deleteNodeCleanup(node)

            conn = self.getEC2Connection(configDict)

            if not node.isIdle:
                # Get EC2 instance and terminate it
                instance = self.__instanceCacheGet(conn, node)

                if instance:
                    self.__terminate_instance(instance)

            # Clean up instance cache
            self.instanceCacheDelete(node.name)
        except ResourceNotFound:
            self.getLogger().warning(
                'Unable to determine AWS instance associated with'
                ' node [{0}]; instance may still be running!'.format(
                    node.name))

    def __terminate_instance(self, instance):
        """
        Wrapper around AWS instance termination
        """

        self.getLogger().info(
            'Terminating instance [{0}]'.format(instance.id))

        try:
            instance.terminate()
        except boto.exception.EC2ResponseError as exc:
            self.getLogger().warning(
                'Error while terminating instance [{0}]: {1}'.format(
                    instance.id, exc.message))

    def transferNode(self, nodeIdSoftwareProfileTuples: Tuple[Node, str],
                     newSoftwareProfileName: str) -> NoReturn:
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
            # pylint: disable=unused-argument
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

    def __get_instance_by_node(self, node, instance_cache):
        """
        Raises:
            NodeNotFound
        """

        configDict = self.getResourceAdapterConfig(
            self.getResourceAdapterConfigProfileByNodeName(node.name))

        conn = self.getEC2Connection(configDict)

        if instance_cache.has_section(node.name):
            # Attempt to get node by cached instance id
            if instance_cache.has_option(node.name, 'instance'):
                instance_id = instance_cache.get(node.name, 'instance')

                reservations = conn.get_all_reservations(filters={
                    'instance_id': instance_id,
                })

                if not reservations:
                    self.getLogger().info(
                        'Unable to get instance (by instance id) for'
                        ' node [%s]' % (node.name))
            elif instance_cache.has_option(node.name, 'reservation_id'):
                # Attempt to get reservation_id from instance cache

                reservation_id = instance_cache.get(
                    node.name, 'reservation_id')

                reservations = conn.get_all_reservations(filters={
                    'tag:Name': node.name,
                    'reservation-id': reservation_id,
                })

                if not reservations:
                    self.getLogger().info(
                        'Unable to get instance (by reservation id)'
                        ' for node [%s]' % (node.name))
            else:
                raise NodeNotFound(
                    'Unable to determine associated AWS instance for'
                    ' node [%s]' % (node.name))

            if reservations:
                return reservations[0].instances[0]

        raise NodeNotFound(
            'Unable to determine associated AWS instance for node [%s]' % (
                node.name))

    def startupNode(self, nodes: List[Node],
                    remainingNodeList: Optional[Union[List[str], None]] = None,
                    tmpBootMethod: Optional[str] = 'n'):
        """
        Start previously stopped instances
        """

        self.getLogger().debug(
            'startupNode(): dbNodes=[%s], remainingNodeList=[%s],'
            ' tmpBootMethod=[%s]' % (
                ' '.join([node.name for node in nodes]),
                ' '.join(remainingNodeList or []), tmpBootMethod))

        # Get instance cache
        instance_cache = self.instanceCacheRefresh()

        # Iterate over specified nodes
        for node in nodes:
            try:
                instance = self.__get_instance_by_node(node, instance_cache)
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

            self.instanceCacheUpdate(
                node.name, added=[('instance', instance.id)])

    def getOptions(self, dbSoftwareProfile: SoftwareProfile,
                   dbHardwareProfile: HardwareProfile) -> dict: \
            # pylint: disable=unused-argument
        """
        Get settings for specified hardware profile
        """
        return {}

    def rebootNode(self, nodes: List[Node],
                   bSoftReset: Optional[bool] = False) -> NoReturn:
        self.getLogger().debug(
            'rebootNode(): nodes=[%s], soft=[%s]' % (
                ' '.join([node.name for node in nodes]), bSoftReset))

        for node in nodes:
            configDict = self.getResourceAdapterConfig(
                self.getResourceAdapterConfigProfileByNodeName(node.name))

            conn = self.getEC2Connection(configDict)

            # Get EC2 instance
            try:
                instance = self.__instanceCacheGet(conn, node)
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
                     bSoftReset: Optional[bool] = False) -> NoReturn:
        self.getLogger().debug(
            'shutdownNode(): nodes=[%s], soft=[%s]' % (
                ' '.join([node.name for node in nodes]), bSoftReset))

        for node in nodes:
            configDict = self.getResourceAdapterConfig(
                self.getResourceAdapterConfigProfileByNodeName(node.name))

            conn = self.getEC2Connection(configDict)

            # Get EC2 instance
            try:
                instance = self.__instanceCacheGet(conn, node)
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
                   updateNodeRequest: dict) -> NoReturn: \
            # pylint: disable=unused-argument
        self.getLogger().debug(
            'updateNode(): node=[{0}]'.format(node.name))

        instance_cache = self.instanceCacheGet(node.name)

        addNodesRequest = {}

        if 'resource_adapter_configuration' not in instance_cache:
            addNodesRequest['resource_adapter_configuration'] = 'default'
        else:
            addNodesRequest['resource_adapter_configuration'] = \
                instance_cache['resource_adapter_configuration']

        if node.state == 'Allocated' and \
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

        self.instanceCacheSet(node.name,
                              addNodesRequest,
                              instance_id=instance_id)

    def get_node_vcpus(self, name: str) -> int:
        """
        Return number of vcpus for node. Value of 'vcpus' configured
        in resource adapter configuration takes precedence over file
        lookup.

        Raises:
            ResourceNotFound

        :param name: node name
        :return: number of vcpus
        :returntype: int
        """

        try:
            instance_cache = self.instanceCacheGet(name)
        except ResourceNotFound:
            return 1

        configDict = self.getResourceAdapterConfig(
            sectionName=instance_cache['resource_adapter_configuration']
            if 'resource_adapter_configuration' in instance_cache else
            None)

        if 'vcpus' in configDict:
            return configDict['vcpus']

        return self.get_instance_size_mapping(configDict['instancetype'])

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

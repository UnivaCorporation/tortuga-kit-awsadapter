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
import socket
import sys
import xml.etree.cElementTree as ET
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, NoReturn, Optional, Union
from typing.io import TextIO

import boto
import boto.ec2
import boto.ec2.autoscale
import boto.vpc
import boto3, botocore
import gevent
import gevent.queue
from boto.ec2.blockdevicemapping import BlockDeviceMapping
from boto.ec2.connection import EC2Connection
from boto.ec2.autoscale import (AutoScaleConnection, LaunchConfiguration,
                                AutoScalingGroup)
from boto.ec2.autoscale.tag import Tag as AutoscaleTag
from boto.ec2.networkinterface import (NetworkInterfaceCollection,
                                       NetworkInterfaceSpecification)
from boto3.resources.base import ServiceResource
from botocore.config import Config
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session
from tortuga.addhost.addHostServerLocal import AddHostServerLocal
from tortuga.addhost.utility import encrypt_insertnode_request
from tortuga.db.models.hardwareProfile import HardwareProfile
from tortuga.db.models.instanceMapping import InstanceMapping
from tortuga.db.models.instanceMetadata import InstanceMetadata
from tortuga.db.models.nic import Nic
from tortuga.db.models.node import Node
from tortuga.db.models.nodeTag import NodeTag
from tortuga.db.models.softwareProfile import SoftwareProfile
from tortuga.db.nodesDbHandler import NodesDbHandler
from tortuga.exceptions.commandFailed import CommandFailed
from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.exceptions.invalidArgument import InvalidArgument
from tortuga.exceptions.nicNotFound import NicNotFound
from tortuga.exceptions.nodeNotFound import NodeNotFound
from tortuga.exceptions.operationFailed import OperationFailed
from tortuga.exceptions.resourceNotFound import ResourceNotFound
from tortuga.node import state
from tortuga.resourceAdapter.resourceAdapter import (DEFAULT_CONFIGURATION_PROFILE_NAME,
                                                     ResourceAdapter)
from tortuga.resourceAdapter.utility import patch_managed_tags

from .exceptions import AWSOperationTimeoutError
from .helpers import (_get_encoded_list, _quote_str,
                      ec2_get_root_block_devices)
from .launchRequest import LaunchRequest, init_node_request_queue
from .settings import SETTINGS


class Aws(ResourceAdapter):
    """
    AWS resource adapter

    """
    __adaptername__ = 'AWS'

    LAUNCH_INITIAL_SLEEP_TIME = 10.0

    settings = SETTINGS

    def __init__(self, addHostSession: Optional[str] = None) -> None:
        super(Aws, self).__init__(addHostSession=addHostSession)

        # Initialize internal flags
        self.__runningOnEc2 = None
        self.__installer_ip: Optional[str] = None

    def getConnectionArgs(self, configDict: Dict[str, Any]) -> Dict[str, Any]:
        connectionArgs = {}

        # only include access/secret key if defined in adapter config
        access_key = configDict.get('awsaccesskey')
        if access_key is not None:
            connectionArgs['aws_access_key_id'] = access_key

            connectionArgs['aws_secret_access_key'] = \
                configDict.get('awssecretkey')

        return connectionArgs

    def getProxyConfig(self, configDict: Dict[str, Any],
                       using_boto3: bool = False) -> Dict[str, Any]:
        proxy_args = {}
        if 'proxy_host' in configDict:
            self._logger.debug('Using proxy for AWS (%s:%s)' % (
                configDict['proxy_host'], configDict['proxy_port']))

            # boto and boto3 have different ways of specifying proxies
            if using_boto3:
                proxy_url_template = '{user_pass}{host}:{port}'
                user_pass = ''
                if 'proxy_user' in configDict:
                    user_pass = configDict['proxy_user']

                    if 'proxy_pass' in configDict:
                        user_pass += ':' + configDict['proxy_pass']

                    user_pass += '@'

                proxy_url = proxy_url_template.format(
                    user_pass=user_pass,
                    host=configDict['proxy_host'],
                    port=configDict['proxy_port']
                )

                # boto assumes it's an HTTP proxy, so we'll do the same
                # for boto3
                proxy_args = {'http': proxy_url}
            else:
                proxy_args['proxy'] = configDict['proxy_host']
                proxy_args['proxy_port'] = configDict['proxy_port']

                # Pass these arguments verbatim to the boto library
                if 'proxy_user' in configDict:
                    proxy_args['proxy_user'] = configDict['proxy_user']

                if 'proxy_pass' in configDict:
                    proxy_args['proxy_pass'] = configDict['proxy_pass']

        return proxy_args

    def getEC2Connection(self, configDict: Dict[str, Any]) -> EC2Connection:
        """
        :raises ConfigurationError: invalid AWS region specified
        """

        connectionArgs = self.getConnectionArgs(configDict)
        proxyArgs = self.getProxyConfig(configDict, using_boto3=False)
        connectionArgs.update(proxyArgs)

        ec2_conn = boto.ec2.connect_to_region(
            configDict['region'],
            **connectionArgs,
        )

        if ec2_conn is None:
            raise ConfigurationError(
                'Invalid AWS region [{}]'.format(configDict['region'])
            )

        return ec2_conn

    def getEC2Connection3(self, configDict: Dict[str, Any]) -> ServiceResource:
        """
        Returns a boto3 conneciton to EC2

        :raises ConfigurationError: invalid AWS region specified
        """
        connectionArgs = self.getConnectionArgs(configDict)
        proxyArgs = self.getProxyConfig(configDict, using_boto3=True)

        # For boto3, we put the proxy configuration in a
        # botocore.config.Config instance
        config = Config(proxies=proxyArgs) if proxyArgs else None

        # Set up the session
        session = boto3.Session(region_name=configDict['region'],
                                **connectionArgs)
        ec2_conn = session.resource('ec2', config=config)

        if ec2_conn is None:
            raise ConfigurationError(
                'Invalid AWS region [{}]'.format(configDict['region'])
            )

        return ec2_conn

    def getAutoScaleConnection(self, configDict: Dict[str, Any]) -> AutoScaleConnection:
        """
        :raises ConfigurationError: invalid AWS region specified
        """

        connectionArgs = self.getConnectionArgs(configDict)

        ec2_conn = boto.ec2.autoscale.connect_to_region(
            configDict['region'],
            **connectionArgs,
        )

        if ec2_conn is None:
            raise ConfigurationError(
                'Invalid AWS region [{}]'.format(configDict['region'])
            )

        return ec2_conn

    def process_config(self, config: Dict[str, Any]):
        #
        # Set the installer IP address if required
        #
        if not config.get('installer_ip', None):
            config['installer_ip'] = self.installer_public_ipaddress

        #
        # Set cloud_init if required
        #
        config['cloud_init'] = config.get('user_data_script_template') or \
            config.get('cloud_init_script_template')

        #
        # Setup block device map
        #
        if 'block_device_map' in config:
            config['block_device_map'] = self.__process_block_device_map(
                config['block_device_map'])

        #
        # DNS specific settings
        #
        if config.get('override_dns_domain', None):
            if not config.get('dns_domain', None):
                config['dns_domain'] = self.private_dns_zone

            #
            # Ensure 'dns_nameservers' defaults to the Tortuga installer
            # as the DNS nameserver
            #
            config['dns_nameservers'] = config.get('dns_nameservers', [])

            if config['installer_ip'] not in config['dns_nameservers']:
                config['dns_nameservers'].append(config['installer_ip'])

        #
        # Attempt to use DNS setting from DHCP Option Set associated with VPC
        #
        if config.get('subnet_id', None) and \
                config.get('use_domain_from_dhcp_option_set', None):
            #
            # Attempt to look up default DNS domain from DHCP options set
            #
            domain = self.__get_vpc_default_domain(config)
            if domain:
                self._logger.info(
                    'Using default domain [%s] from DHCP option set',
                    domain
                )
                config['dns_domain'] = domain
                config['override_dns_domain'] = True

        if config.get('override_dns_domain', None):
            self._logger.debug(
                'Using DNS domain {0} for compute nodes'.format(
                    config['dns_domain']))
        #
        # Credentials from vault
        #
        if config.get('credential_vault_path'):
            # Check in vault for our keys
            record = self._cm.loadFromVault(config.get('credential_vault_path'))
            if record is not None:
                config['awsaccesskey'] = record.get('data',{}).get('aws_access_key_id')
                config['awssecretkey'] = record.get('data',{}).get('aws_secret_access_key')

    def __get_vpc_default_domain(self, config: Dict[str, Any]) -> str: \
            # pylint: disable=no-self-use
        """Returns custom DNS domain associated with DHCP option set,
        otherwise returns None

        Raises:
            ConfigurationError
        """

        try:
            vpcconn = boto.vpc.connect_to_region(
                config['region'],
                aws_access_key_id=config.get('awsaccesskey'),
                aws_secret_access_key=config.get('awssecretkey')
            )
        except boto.exception.NoAuthHandlerFound:
            raise ConfigurationError(
                'Unable to authenticate AWS connection: check credentials')

        try:
            # Look up configured subnet_id
            subnet = vpcconn.get_all_subnets(
                subnet_ids=[config.get('subnet_id', None)])[0]

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

            self._logger.debug(
                '__process_block_device_map(): device=[%s]' % (device))

            elements = mapping.split(':')
            if not elements:
                self._logger.debug(
                    'Ignoring malformed mapping for device [%s]' % (device))

                continue

            bdt = boto.ec2.blockdevicemapping.BlockDeviceType()

            if elements[0].startswith('none'):
                self._logger.warning(
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
                        self._logger.warning(
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

        self._logger.debug('block device map: %s' % (bdm))

        return bdm

    def __get_instance_by_instance_id(self, conn: EC2Connection,
                                      instance_id: str) \
            -> Optional[boto.ec2.instance.Instance]:
        result = conn.get_only_instances(instance_ids=[instance_id])
        if not result:
            return None

        return result[0]

    def delete_scale_set(self,
              name: str,
              resourceAdapterProfile: str):

        """
        Delete an existing scale set

        :raises InvalidArgument:
        """

        configDict = self.get_config(
            resourceAdapterProfile
        )

        autoconn = self.getAutoScaleConnection(configDict)
        try:
            autoconn.delete_auto_scaling_group(name, force_delete=True)
        except boto.exception.BotoServerError as ex:
            if not ex.message.startswith("AutoScalingGroup name not found"):
                raise
        finally:
            try:
                autoconn.delete_launch_configuration(name)
            except boto.exception.BotoServerError as ex:
                if not ex.message.startswith("Launch configuration name not found"):
                    raise

    def create_launch_template(self,
              name: str,
              resourceAdapterProfile: str,
              hardwareProfile: str,
              softwareProfile: str,
              adapter_args: dict,
              configDict: dict={}):
        """
        Create an AWS launch template, which can be used for launching
        individual instances or auto scaling groups.

        :param name: name of resulting launch template
        :param resourceAdapterProfile: name of resource adapter profile
        :param hardwareProfile: name of hardware profile
        :param softwareProfile: name of software profile
        :param adapter_args: dict of extra args
        :param configDict: resource adapter configuration dict (optional);
            if not provided, it will be loaded from the database

        :raises InvalidArgument:

        :return: launch template dict (see boto3 docs for details)
        """
        if not configDict:
            configDict = self.get_config(resourceAdapterProfile)

        # Get boto3 EC2 connection
        conn3 = self.getEC2Connection3(configDict)

        # Set up insertnode_request
        insertnode_request = {
            'softwareProfile': softwareProfile,
            'hardwareProfile': hardwareProfile,
            'resource_adapter_configuration': resourceAdapterProfile,
        }
        encrypted_insertnode_request = encrypt_insertnode_request(
            self._cm.get_encryption_key(),
            insertnode_request
        )

        # Set up addNodesRequest
        addNodesRequest = {
            'hardwareProfile': hardwareProfile,
            'softwareProfile': softwareProfile,
        }

        # Set up request parameters
        template_args = self.__get_common_launch_args3(
            conn3,
            configDict,
            addNodesRequest=addNodesRequest,
            insertnode_request=encrypted_insertnode_request
        )
        # Add AMI
        template_args['ImageId'] = configDict['ami']

        # Get spot price, if any
        spot_price = adapter_args.get('spot_request',{}).get('price')
        if spot_price is None:
            spot_price = configDict.get('spot_price')
        if spot_price:
            template_args['InstanceMarketOptions'] = {
                'MarketType': 'spot',
                'SpotOptions': {'MaxPrice': spot_price},
            }

        # Try to create a launch template
        try:
            launch_template = conn3.meta.client.create_launch_template(
                LaunchTemplateName=name,
                LaunchTemplateData=template_args
            )
        except Exception as ex:
            self._logger.exception("Error creating launch template")
            raise ex

        return launch_template

    def create_instance_template(self, *args, **kwargs):
        """
        This method just calls the create_launch_template() method.
        It exists simply to provide a consistent method name for creating
        instance templates across all adapter kits.
        """
        return self.create_launch_template(*args, **kwargs)

    def create_scale_set(self,
              name: str,
              resourceAdapterProfile: str,
              hardwareProfile: str,
              softwareProfile: str,
              minCount: int,
              maxCount: int,
              desiredCount: int,
              adapter_args: dict):

        """
        Create a new scale set

        :raises InvalidArgument:
        """

        configDict = self.get_config(
            resourceAdapterProfile
        )

        autoconn = self.getAutoScaleConnection(configDict)
        conn = self.getEC2Connection(configDict)
        insertnode_request = {
            'softwareProfile': softwareProfile,
            'hardwareProfile': hardwareProfile,
            'apply_tags_post_launch': False,
            'resource_adapter_configuration': resourceAdapterProfile,
        }
        lcArgs = self.__get_launch_config_args(
            conn,
            configDict,
            encrypt_insertnode_request(self._cm.get_encryption_key(), insertnode_request)
        )
        spot_price = adapter_args.get('spot_request',{}).get('price')
        if spot_price is None:
            spot_price = configDict.get('spot_price')
        lc = LaunchConfiguration(name=name, image_id=configDict['ami'],
                         spot_price=spot_price,
                         **lcArgs)
        autoconn.create_launch_configuration(lc)

        # Get list of boto.ec2.autoscale.tag.Tag objects to apply to the
        # auto-scaling group and propagate to new instances
        tags = self._get_scale_set_tags(name, configDict, hardwareProfile,
                                        softwareProfile)

        try:
            ag = AutoScalingGroup(group_name=name,
                          vpc_zone_identifier=configDict.get("subnet_id"),
                          launch_config=lc, min_size=minCount, max_size=maxCount,
                          desired_capacity=desiredCount,
                          health_check_period=configDict.get("healthcheck_period"),
                          connection=autoconn, tags=tags)
            autoconn.create_auto_scaling_group(ag)
        except Exception as ex:
            autoconn.delete_launch_configuration(lc.name)
            raise ex

    def update_scale_set(self,
              name: str,
              resourceAdapterProfile: str,
              hardwareProfile: str,
              softwareProfile: str,
              minCount: int,
              maxCount: int,
              desiredCount: int,
              adapter_args: dict):

        """
        Update an existing scale set

        :raises InvalidArgument:
        """

        configDict = self.get_config(
            resourceAdapterProfile
        )

        autoconn = self.getAutoScaleConnection(configDict)
        conn = self.getEC2Connection(configDict)
        insertnode_request = {
                   'softwareProfile': softwareProfile,
                   'hardwareProfile': hardwareProfile,
        }
        lcArgs = self.__get_launch_config_args(
            conn,
            configDict,
            encrypt_insertnode_request(self._cm.get_encryption_key(), insertnode_request)
        )
        spot_price = adapter_args.get('spot_request',{}).get('price')
        if spot_price is None:
            spot_price = configDict.get('spot_price')
        lc = LaunchConfiguration(name=name, image_id=configDict['ami'],
                         spot_price=spot_price,
                         **lcArgs)
        try:
            ag = AutoScalingGroup(group_name=name,
                          vpc_zone_identifier=configDict.get("subnet_id"),
                          launch_config=lc, min_size=minCount, max_size=maxCount,
                          desired_capacity=desiredCount,
                          health_check_period=configDict.get("healthcheck_period"),
                          connection=autoconn)
            ag.update()
        except Exception as ex:
            raise ex

    def _get_scale_set_tags(self, group_name: str, configDict: Dict[str, Any],
                            hardwareprofile_name: str,
                            softwareprofile_name: str) -> List[AutoscaleTag]:

        # Get dict of key-value pairs for default tags
        tag_dict = self.get_initial_tags(configDict, hardwareprofile_name,
                                         softwareprofile_name)

        # Convert to a list of boto.ec2.autoscale.tag.Tag objects
        # Set "propagate-at-launch" to be always True so that instances in
        # the group are assigned the tags when they are launched.
        autoscale_tags = [
            AutoscaleTag(
                resource_id=group_name, resource_type='auto-scaling-group',
                key=k, value=v, propagate_at_launch=True
            )
            for k, v in tag_dict.items()
        ]

        return autoscale_tags

    def start(self, addNodesRequest: dict, dbSession: Session,
              dbHardwareProfile: HardwareProfile,
              dbSoftwareProfile: Optional[SoftwareProfile] = None) \
            -> List[Node]:
        """
        Create one or more nodes

        :raises InvalidArgument:
        """

        self._logger.debug(
            'start(addNodeRequest=[%s], dbSession=[%s],'
            ' dbHardwareProfile=[%s], dbSoftwareProfile=[%s])' % (
                addNodesRequest, dbSession, dbHardwareProfile.name,
                dbSoftwareProfile.name if dbSoftwareProfile else '(none)'))

        result = super().start(addNodesRequest, dbSession, dbHardwareProfile,
                               dbSoftwareProfile)

        # Get connection to AWS
        launch_request = LaunchRequest(
            hardwareprofile=dbHardwareProfile,
            softwareprofile=dbSoftwareProfile,
        )
        launch_request.addNodesRequest = addNodesRequest

        # resource_adapter_configuration is set through the validation API;
        # ensure sane default is used
        cfgname = addNodesRequest.get(
            'resource_adapter_configuration',
            DEFAULT_CONFIGURATION_PROFILE_NAME)

        launch_request.configDict = self.get_config(cfgname)
        if not launch_request.configDict:
            raise InvalidArgument(
                'Unable to get resource adapter configuration'
            )

        launch_request.conn = self.getEC2Connection(launch_request.configDict)
        launch_request.conn3 = \
            self.getEC2Connection3(launch_request.configDict)

        if 'nodeDetails' in addNodesRequest and \
                addNodesRequest['nodeDetails']:
            # Instances already exist, create node records
            if 'metadata' in addNodesRequest['nodeDetails'][0] and \
                    'ec2_instance_id' in \
                    addNodesRequest['nodeDetails'][0]['metadata']:
                # inserting nodes based on metadata
                nodes = self.__insert_nodes(dbSession, launch_request)

                dbSession.commit()

                return nodes

        if 'spot_instance_request' in addNodesRequest or \
            launch_request.configDict.get('enable_spot'):
            # handle EC2 spot instance request
            return self.__request_spot_instances(
                dbSession, launch_request
            )

        nodes = self.__add_active_nodes(dbSession, launch_request)

        # This is a necessary evil for the time being, until there's
        # a proper context manager implemented.
        self.addHostApi.clear_session_nodes(nodes)

        result.extend(nodes)

        return result

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

        self._logger.info(
            'Inserting %d node(s)',
            len(launch_request.addNodesRequest['nodeDetails']),
        )

        vcpus = self.get_instance_size_mapping(
            launch_request.configDict['instancetype']
        ) if 'vcpus' not in launch_request.configDict else \
            launch_request.configDict['vcpus']

        nodes: List[Node] = []

        for nodedetail in launch_request.addNodesRequest['nodeDetails']:
            node = self.__upsert_node(
                session,
                launch_request,
                nodedetail,
                metadata={
                    'vcpus': vcpus,
                },
            )
            if not node:
                continue

            nodes.append(node)

        return nodes

    def __get_node_by_name(self, session: Session, node_name: str) \
        -> Optional[Node]:
        try:
            return session.query(Node).filter(
                Node.name==node_name  # noqa
            ).one()
        except NoResultFound:
            pass

        return None

    def __get_node_by_instance(self, session: Session,
                               instance_id: str) -> Optional[Node]:
        try:
            return session.query(InstanceMapping).filter(
                InstanceMapping.instance==instance_id  # noqa
            ).one().node
        except NoResultFound:
            pass

        return None

    def __get_spot_instance_metadata(self, session: Session, sir_id: str) -> Optional[InstanceMetadata]:
        try:
            return session.query(
                InstanceMetadata
            ).filter(InstanceMetadata.key==sir_id).one()  # noqa
        except NoResultFound:
            pass

        return None

    def __upsert_node(self, session: Session, launch_request: LaunchRequest,
                      nodedetail: dict, *,
                      metadata: Optional[dict] = None) -> Optional[Node]:
        """This method is used to add/update node entries after spot
        instances have been fulfilled.

        :raises InvalidArgument:
        """

        instance_id: Optional[str] = \
            nodedetail['metadata']['ec2_instance_id'] \
            if 'metadata' in nodedetail and \
            'ec2_instance_id' in nodedetail['metadata'] else None
        if not instance_id:
            # TODO: currently not handled
            self._logger.error(
                'instance_id not set in metadata. Unable to insert AWS nodes'
                ' without backing instance'
            )

            return None

        instance = self.__get_instance_by_instance_id(
            launch_request.conn, instance_id
        )
        if not instance:
            self._logger.warning(
                'Error inserting node [%s]. AWS instance [%s] does not exist',
                instance_id,
            )

            return None

        node_created = False

        # Try to get node by instance, or by the node name
        node = self.__get_node_by_instance(session, instance_id)
        if node is None:
            node_name = launch_request.addNodesRequest.get('node_name', None)
            if node_name is not None:
                node = self.__get_node_by_name(session, node_name)

        if node is None:
            try:
                node = self.__create_node(
                    session,
                    launch_request,
                    nodedetail,
                    metadata=metadata,
                )
                # We apply tags as long as the addNodesRequest does not
                # explicitly instruct us not to.
                apply_tags = launch_request.addNodesRequest.get(
                    'apply_tags_post_launch', True
                )
                if apply_tags:
                    self._tag_instance(launch_request.configDict,
                                       launch_request.conn, node, instance)
                node_created = True

            except InvalidArgument:
                self._logger.exception(
                    'Error creating new node record in insert workflow'
                )
                raise

        else:
            # This is the "update" branch of upsert
            self._logger.debug(
                'Found existing node record [%s] for instance id [%s]',
                node.name, instance_id
            )
            ip = nodedetail['metadata']['ec2_ipaddress']
            self._pre_add_host(node.name, launch_request.hardwareprofile.name,
                               launch_request.softwareprofile.name, ip)

            # Update node
            node.state = state.NODE_STATE_PROVISIONED
            node.addHostSession = self.addHostSession
            primary_nic = get_primary_nic(node.nics)
            primary_nic.ip = ip

            # Get node tags from DB and apply to instance
            tag_dict = {tag.name: tag.value for tag in node.tags}
            self._tag_instance(launch_request.configDict, launch_request.conn,
                               node, instance, tags=tag_dict)

        # set node properties
        node.instance = InstanceMapping(
            instance=instance_id,
            resource_adapter_configuration=self.load_resource_adapter_config(
                session,
                launch_request.addNodesRequest.get('resource_adapter_configuration'))
        )

        # Try to set public hostname
        if instance.public_dns_name:
            node.public_hostname = instance.public_dns_name

        # attempt to find matching spot instance request
        if 'spot_instance_request_id' in nodedetail['metadata']:
            sir_id = nodedetail['metadata']['spot_instance_request_id']

            result = self.__get_spot_instance_metadata(session, sir_id)
            if not result:
                self._logger.error(
                    'Unable to find matching spot instance request: %s',
                    sir_id,
                )

                return None

            self._logger.info(
                'Matching spot instance request [%s] to instance id [%s]',
                sir_id, instance_id
            )

            node.instance.instance_metadata.append(result)

        if node_created:
            # only fire the new node event if creating the record for the
            # first time
            self.fire_provisioned_event(node)

        return node

    def __create_node(self, session: Session, launch_request: LaunchRequest,
                      nodedetail: dict, *,
                      metadata: Optional[dict] = None) -> Node:
        """
        :raises InvalidArgument:
        """
        if launch_request.hardwareprofile.nameFormat != '*':
            # Generate host name for spot instance
            fqdn = self.addHostApi.generate_node_name(
                session,
                launch_request.hardwareprofile.nameFormat,
                dns_zone=launch_request.configDict.get('dns_domain')
            )
        else:
            fqdn = nodedetail.get('name')
            if fqdn is None:
                raise InvalidArgument(
                    'Unable to insert node(s) without name'
                )

        # TODO: handle this not being defined
        ip = nodedetail['metadata']['ec2_ipaddress']

        self._pre_add_host(
            fqdn,
            launch_request.hardwareprofile.name,
            launch_request.softwareprofile.name,
            ip,
        )

        node = Node(
            name=fqdn,
            softwareprofile=launch_request.softwareprofile,
            hardwareprofile=launch_request.hardwareprofile,
            state=state.NODE_STATE_PROVISIONED,
            addHostSession=self.addHostSession,
            nics=[Nic(ip=ip, boot=True)],
        )

        if metadata is not None and 'vcpus' in metadata:
            node.vcpus = metadata['vcpus']

        return node

    def __request_spot_instances(
                self,
                session: Session,
                launch_request: LaunchRequest
            ) -> List[Node]:
        """
        Make request for EC2 spot instances. Spot instance arguments are
        passed through 'addNodesRequest' in the dictionary
        'spot_instance_request.

        Minimally, 'price' needs to be specified. Sane defaults exist for all
        other values, similar to those used in the AWS Management Console.

        :raises OperationFailed:
        """

        addNodesRequest = launch_request.addNodesRequest

        cfgname = addNodesRequest.get('resource_adapter_configuration') \
            if addNodesRequest else DEFAULT_CONFIGURATION_PROFILE_NAME

        dbHardwareProfile = launch_request.hardwareprofile
        dbSoftwareProfile = launch_request.softwareprofile

        configDict = launch_request.configDict

        conn = launch_request.conn

        self._logger.debug(
            'request_spot_instances: addNodesRequest=[%s], '
            ' dbHardwareProfile=[%s], dbSoftwareProfile=[%s])',
            addNodesRequest,
            dbHardwareProfile.name,
            dbSoftwareProfile.name,
        )

        self._validate_ec2_launch_args(conn, configDict)

        spot_price = addNodesRequest.get('spot_instance_request',{}).get('price')
        if spot_price is None:
            spot_price = configDict.get('spot_price')

        # Set up insertnode_request
        insertnode_request = {
            'softwareProfile': dbSoftwareProfile.name,
            'hardwareProfile': dbHardwareProfile.name,
            'resource_adapter_configuration': cfgname,
        }

        try:
            if configDict['use_instance_hostname']:
                nodes: List[Node] = []

                # Get the private dns domain name
                dnsdomain = None
                if configDict.get('override_dns_domain', None):
                    dnsdomain = configDict.get('dns_domain', None)

                # Add any tags from the addNodesRequest (i.e., that aren't
                # directly attached to the adapter profile configuration)
                # so they can be applied once the spot instance comes online
                requested_tags = addNodesRequest.get('tags', {})
                if requested_tags:
                    insertnode_request['tags'] = requested_tags

                # Encrypt the insertnode_request
                encrypted_insertnode_request = encrypt_insertnode_request(
                    self._cm.get_encryption_key(), insertnode_request
                )
                args = self.__get_request_spot_instance_args(
                    conn,
                    addNodesRequest,
                    configDict,
                    insertnode_request=encrypted_insertnode_request
                )

                resv = conn.request_spot_instances(
                    spot_price,
                    configDict['ami'],
                    **args,
                )

                self.__post_add_spot_instance_request(
                    session,
                    resv,
                    dbHardwareProfile,
                    dbSoftwareProfile,
                    cfgname=cfgname,
                    dnsdomain=dnsdomain,
                )
            else:
                nodes = self.__create_nodes(session,
                                            configDict,
                                            dbHardwareProfile,
                                            dbSoftwareProfile,
                                            count=addNodesRequest['count'],
                                            initial_state='Allocated')

                session = self.session

                for node in nodes:
                    # Add the node name to the insertnode_request and
                    # instructions to skip a step in the validation (usually
                    # an error is thrown if the hardware profile doesn't allow
                    # the node name to be set, but a name is included in the
                    # addNodesRequest)
                    insertnode_request.update(
                        {
                            'node_name': node.name,
                            'skip_hostname_hwprofile_validation': True,
                        }
                    )

                    # Encrypt
                    encrypted_insertnode_request = encrypt_insertnode_request(
                        self._cm.get_encryption_key(), insertnode_request
                    )
                    args = self.__get_request_spot_instance_args(
                        conn,
                        addNodesRequest,
                        configDict,
                        node=node,
                        insertnode_request=encrypted_insertnode_request
                    )

                    resv = conn.request_spot_instances(
                        spot_price,
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

                    self.__post_add_spot_instance_request(
                        session,
                        resv,
                        dbHardwareProfile,
                        dbSoftwareProfile,
                        cfgname=cfgname,
                    )
                # this may be redundant...
                session.commit()
        except boto.exception.EC2ResponseError as exc:
            raise OperationFailed(
                'Error requesting EC2 spot instances: {0} ({1})'.format(
                    exc.message, exc.error_code))
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(
                'Fatal error making spot instance request')
            raise

        return nodes

    def __get_request_spot_instance_args(
                self,
                conn: EC2Connection,
                addNodesRequest: dict,
                configDict: Dict[str, Any],
                node: Optional[Node] = None,
                insertnode_request: Optional[bytes] = None
            ) -> Dict[str, Any]:
        """
        Create dict of args for boto request_spot_instances() API
        """

        # Get common AWS launch args
        args = self.__get_common_launch_args(
            conn,
            configDict,
            node=node,
            addNodesRequest=addNodesRequest,
            insertnode_request=insertnode_request
        )

        args['count'] = addNodesRequest.get('count', 1)

        if 'launch_group' in addNodesRequest:
            args['launch_group'] = addNodesRequest['launch_group']

        if 'user_data' in args:
            # Due to a bug in "boto<=2.4.9", it is necessary to convert
            # user_data to bytes before passing it to launch
            args['user_data'] = args['user_data'].encode('utf-8')

        return args

    def __post_add_spot_instance_request(
                self,
                session: Session,
                resv: boto.ec2.instance.Reservation,
                hardwareprofile: HardwareProfile,
                softwareprofile: SoftwareProfile,
                cfgname: str = DEFAULT_CONFIGURATION_PROFILE_NAME,
                dnsdomain: str = None
            ) -> None:
        """
        Persist spot instance request to database. Notify awsspotd of new
        spot instance requests.
        """
        for r in resv:
            request = {
                'action': 'add',
                'spot_instance_request_id': r.id,
                'softwareprofile': softwareprofile.name,
                'hardwareprofile': hardwareprofile.name,
            }

            if dnsdomain:
                request['dnsdomain'] = dnsdomain

            if cfgname:
                request['resource_adapter_configuration'] = cfgname

            session.add(
                InstanceMetadata(
                    key=r.id,
                    value=json.dumps(request),
                )
            )

    def cancel_spot_instance_requests(self):
        """TODO"""

    def validate_start_arguments(self, addNodesRequest: Dict[str, Any],
                                 dbHardwareProfile: HardwareProfile,
                                 dbSoftwareProfile: SoftwareProfile) -> None: \
            # pylint: disable=unused-argument

        """
        Ensure arguments to start() instances are valid

        :raises InvalidArgument:
        :raises ConfigurationError:
        """

        super().validate_start_arguments(
            addNodesRequest, dbHardwareProfile, dbSoftwareProfile
        )

        configDict = self.get_config(
            addNodesRequest['resource_adapter_configuration']
        )

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
            -> Dict[str, Optional[str]]:
        """
        Returns dict containing resource adapter configuration metadata

        """

        installerIp: Optional[str] = config.get('installer_ip')
        if installerIp is None:
            # handle situation where installer hostname cannot be resolved
            try:
                installerIp = self._get_installer_ip(
                    hardwareprofile=node.hardwareprofile
                    if node else None
                )
            except socket.gaierror:
                pass

        dns_domain_value = _quote_str(config['dns_domain']) \
            if config.get('dns_domain') else None

        return {
            'installerHostName': self.installer_public_hostname,
            'installerIp': _quote_str(installerIp),
            'adminport': self._cm.getAdminPort(),
            'cfmuser': self._cm.getCfmUser(),
            'cfmpassword': self._cm.getCfmPassword(),
            'override_dns_domain':
            str(config.get('override_dns_domain', False)),
            'dns_options': _quote_str(config['dns_options'])
            if config.get('dns_options') else None,
            'dns_domain': dns_domain_value,
            'dns_nameservers':
            _get_encoded_list(config.get('dns_nameservers')),
        }

    def __get_common_user_data_content(
            self, user_data_settings: Dict[str, str],
            insertnode_request: Optional[bytes] = None) \
            -> str:  # pylint: disable=no-self-use
        settings =  """\
installerHostName = '%(installerHostName)s'
installerIpAddress = %(installerIp)s
port = %(adminport)d

# DNS resolution settings
override_dns_domain = %(override_dns_domain)s
dns_options = %(dns_options)s
dns_search = %(dns_domain)s
dns_domain = %(dns_domain)s
dns_nameservers = %(dns_nameservers)s
""" % (user_data_settings)
        if insertnode_request is None:
            settings += """
# CFM Auth
cfmUser = '%(cfmuser)s'
cfmPassword = '%(cfmpassword)s'
insertnode_request = None
""" % (user_data_settings)
        else:
            settings += """
# Insert_node
insertnode_request = %s
""" % (insertnode_request)
        return settings

    def __get_user_data(self, config: Dict[str, str],
                        node: Optional[Node] = None,
                        insertnode_request: Optional[bytes] = None) -> str:
        """
        Return metadata to be associated with each launched instance
        """

        if 'user_data_script_template' in config:
            return self.__get_user_data_script(
                config,
                node=node,
                insertnode_request=insertnode_request
            )

        # process template file specified by 'cloud_init_script_template'
        # as YAML cloud-init configuration data
        return self.expand_cloud_init_user_data_template(config, node=node)

    def generate_startup_script(self, config: Dict[str, str],
                                node: Optional[Node] = None,
                                insertnode_request: Optional[bytes] = None) \
            -> str:
        """
        Build a node/instance-specific startup script that will initialize
        VPN, install Puppet, and bootstrap the instance.

        :param configDict: resource adapter configuration settings
        :param node: Node instance, optional
        :param insertnode_request: encrypted insertnode_request, optional

        :return: full startup script as a `str`
        """
        settings_dict = self.__get_common_user_data_settings(config, node)

        result = ''
        with open(config['user_data_script_template']) as fp:
            for inp in fp.readlines():
                if inp.startswith('### SETTINGS'):
                    # substitute "SETTINGS" section in template
                    result += self.__get_common_user_data_content(
                        settings_dict, insertnode_request
                    )
                    continue
                result += inp
        return result

    def __get_user_data_script(self, config: Dict[str, str],
                               node: Optional[Node] = None,
                               insertnode_request: Optional[bytes] = None) \
            -> str:

        result = self.generate_startup_script(
            config,
            node=node,
            insertnode_request=insertnode_request
        )

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

        try:
            instances = self.__launchEC2(
                launch_request.conn3, launch_request.configDict,
                count=launch_request.addNodesRequest['count'],
                addNodesRequest=launch_request.addNodesRequest,
            )
        except Exception as exc:
            # AWS error, unable to proceed
            self._logger.exception('AWS error launching instances')

            raise CommandFailed(str(exc))

        launch_request.node_request_queue = \
            [dict(instance=instance, status='launched')
             for instance in instances]

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

        conn3 = launch_request.conn3
        configDict = launch_request.configDict
        addNodesRequest = launch_request.addNodesRequest
        dbHardwareProfile = launch_request.hardwareprofile
        dbSoftwareProfile = launch_request.softwareprofile

        count = addNodesRequest['count']

        self._logger.info(
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

        try:
            for node_request in launch_request.node_request_queue:
                # Launch instance
                try:
                    node_request['instance'] = \
                        self.__launchEC2(
                            conn3,
                            configDict,
                            node=node_request['node'],
                            addNodesRequest=addNodesRequest
                        )[0]

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

                    self._logger.exception(
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

            self._logger.exception(
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

            self._logger.warning(warnmsg)

        return [node_request['node']
                for node_request in node_request_queue
                if node_request['status'] == 'running']

    def __aws_check_instance_state(self, instance):
        try:
            instance.reload()
        except botocore.exceptions.ClientError as ex:
            # Not even the sample boto code appears to handle this
            # scenario. It appears there's a race condition between
            # creating an instance and polling for the instance
            # status.
            # If the poll occurs before the instance has been
            # "registered" by the EC2 backend, it's possible the
            # update() call will raise a "not found" exception.
            # Subsequent update() calls are successful.

            self._logger.debug(
                f'Ignoring exception raised while updating instance: {ex}'
            )

            return None

        return instance.state['Name']

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

            self._logger.debug(
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

            if instance.state['Name'] != 'pending':
                # Instance in unexpected state, report error
                node_request['status'] = instance.state['Name']

                self._logger.error(
                    'Instance [%s] in unexpected state [%s]' % (
                        instance.state['Name']))

                raise OperationFailed(
                    'Error launching instance: state=[{0}]'.format(
                        instance.state['Name']))

    def __failed_launch_cleanup_handler(self, session: Session,
                                        node_request: dict) -> None:
        """
        Clean up routine Run when instance does not reach running state
        within create timeout period or reaches unexpected state.
        """

        self._logger.error(
            'Terminating failed instance [{0}]'.format(
                node_request['instance'].id))

        node = node_request['node'] if 'node' in node_request else None

        # this step may not be necessary but ensure instance isn't left
        # running if any transient condition caused the failure

        try:
            node_request['instance'].terminate()
        except boto.exception.EC2ResponseError as exc:
            self._logger.warning(
                'Error while terminating instance [{0}]: {1}'.format(
                    node_request['instance'].id, exc.message))

        if node:
            # Clean up instance cache
            session.delete(node.instance)

    def __wait_for_instance_coroutine(
            self, launch_request: LaunchRequest, dbSession: Session,
            queue: gevent.queue.JoinableQueue) -> NoReturn:
        """
        Process one node request from queue
        """

        configDict = launch_request.configDict

        while True:
            node_request = queue.get()

            try:
                with gevent.Timeout(
                        configDict['launch_timeout'], TimeoutError):
                    self.process_item(launch_request, node_request)

                    self._logger.info(
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

                self._logger.error(logmsg)

                # Mark request as failed
                node_request['status'] = 'error'

                # Terminate instance
                self.__failed_launch_cleanup_handler(dbSession, node_request)
            finally:
                queue.task_done()

    def __wait_for_instances(self, dbSession: Session,
                             launch_request: LaunchRequest) -> None:
        """
        :raises ConfigurationError:
        :raises NicNotFound:
        """

        self._logger.info(
            'Waiting for session [%s] to complete...', self.addHostSession,
        )

        # Initialize workqueue
        queue = gevent.queue.JoinableQueue()

        # Create coroutines to wait for instances to reach running state.
        #
        # Process only 10 instances at a time to prevent triggering AWS
        # API rate limiting.
        for _ in range(min(len(launch_request.node_request_queue), 10)):
            gevent.spawn(
                self.__wait_for_instance_coroutine,
                launch_request,
                dbSession,
                queue,
            )

        # Enqueue node requests
        for node_request in launch_request.node_request_queue:
            queue.put(node_request)

        # Process queue
        queue.join()

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

            self._logger.debug(
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

            if instance.public_dns_name:
                node.public_hostname = instance.public_dns_name

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

        # This node is ready
        node_request['status'] = 'running'

        node.state = state.NODE_STATE_PROVISIONED

        self.fire_provisioned_event(node)

    def __get_node_name(self, launch_request, instance):
        if launch_request.configDict['use_reverse_dns_hostname']:
            ip = instance.private_ip_address

            # use reverse DNS host name
            self._logger.debug(
                'Using reverse DNS lookup of IP [{}]'.format(ip))

            try:
                hostent = socket.gethostbyaddr(ip)

                return hostent[0]
            except socket.herror:
                name = instance.private_dns_name

                self._logger.debug(
                    'Error performing reverse lookup.'
                    ' Using AWS-assigned name: [{}]'.format(name))

                return name

        if launch_request.configDict.get('override_dns_domain', None):
            hostname, _ = instance.private_dns_name.split('.', 1)

            # Use EC2-assigned host name with 'private_dns_zone'.
            return '{0}.{1}'.format(
                hostname, launch_request.configDict.get('dns_domain', None))

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

        # get vcpus for nodes being added
        vcpus = self.get_instance_size_mapping(
            configDict['instancetype']
        ) if 'vcpus' not in configDict else configDict['vcpus']

        nodes = []

        for _ in range(count):
            node = Node()

            # Generate the 'internal' host name
            if hardwareprofile.nameFormat != '*':
                # Generate node name
                node.name = self.addHostApi.generate_node_name(
                    session,
                    hardwareprofile.nameFormat,
                    dns_zone=configDict.get('dns_domain', None)
                )

            node.state = initial_state
            node.hardwareprofile = hardwareprofile
            node.softwareprofile = softwareprofile
            node.addHostSession = self.addHostSession
            node.vcpus = vcpus

            #
            # Set initial tags for the node
            #
            initial_tags = self.get_initial_tags(
                configDict, hardwareprofile.name, softwareprofile.name,
                node=node
            )
            for k, v in initial_tags.items():
                tag = NodeTag(name=k, value=v)
                node.tags.append(tag)

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

    def _validate_ec2_launch_args(self,
                                  conn: Union[EC2Connection, ServiceResource],
                                  configDict: Dict[str, Any]):

        # NOTE: the commented out portions are not boto3-compatible
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

        is_boto3_conn = isinstance(conn, ServiceResource)
        ConnException = botocore.exceptions.ClientError if is_boto3_conn \
            else boto.exception.EC2ResponseError

        # Create placement group if needed.
        if configDict.get('placementgroup'):
            try:
                self._logger.debug(
                    'Attempting to create placement group [%s]' % (
                        configDict['placementgroup']))

                if is_boto3_conn:
                    conn.create_placement_group(
                        GroupName=configDict['placementgroup'],
                        Strategy='cluster',
                    )
                else:
                    conn.create_placement_group(configDict['placementgroup'],
                                                strategy='cluster')

                self._logger.debug(
                    'Created placement group [%s]' % (
                        configDict['placementgroup']))

            except ConnException as ex:
                # let this fail, group may already exist
                extErrMsg = str(ex) if is_boto3_conn \
                    else self.__parseEC2ResponseError(ex) 

                self._logger.warning(
                    'Unable to create placement group [%s] (%s)' % (
                        configDict['placementgroup'],
                        extErrMsg or '<no reason provided>'))

    def __get_launch_config_args(
            self, conn: EC2Connection, configDict: Dict[str, Any],
            insertnode_request: bytes) -> Dict[str, Any]:
        """
        Return key-value pairs of arguments for passing to launch API
        """

        args = {
            'key_name': configDict['keypair'],
            'instance_type': configDict['instancetype'],
        }

        value = configDict.get('zone')
        if value is not None:
            args['placement'] = value

        value = configDict.get('placementgroup')
        if value is not None:
            args['placement_group'] = value

        if configDict['cloud_init']:
            args['user_data'] = self.__get_user_data(configDict,
                                  node=None,
                                  insertnode_request=insertnode_request)

        if 'aki' in configDict and configDict['aki']:
            # Override kernel used for new instances
            args['kernel_id'] = configDict['aki']

        if 'ari' in configDict and configDict['ari']:
            # Override ramdisk used for new instances
            args['ramdisk_id'] = configDict['ari']

        # Build 'block_device_mappings'
        mappings = \
            self.__build_block_device_map(
                conn,
                configDict['block_device_map']
                if 'block_device_map' in configDict else None,
                configDict['ami'])

        args['block_device_mappings'] = [mappings]

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

        # Security groups
        args['security_groups'] = configDict.get('securitygroup', [])

        return args

    def __get_common_launch_args(
            self, conn: EC2Connection, configDict: Dict[str, Any],
            node: Optional[Node] = None, *,
            addNodesRequest: Optional[dict] = None,
            insertnode_request: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Return key-value pairs of arguments for passing to launch API
        """

        args = {
            'key_name': configDict['keypair'],
            'instance_type': configDict['instancetype'],
        }

        value = configDict.get('zone')
        if value is not None:
            args['placement'] = value

        value = configDict.get('placementgroup')
        if value is not None:
            args['placement_group'] = value

        if configDict['cloud_init']:
            args['user_data'] = self.__get_user_data(configDict, node=node,
                                  insertnode_request=insertnode_request)

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

            private_ip_address = get_private_ip_address_argument(
                addNodesRequest
            ) if addNodesRequest else None

            if private_ip_address:
                self._logger.debug(
                    'Assigning ip address [%s] to new instance',
                    private_ip_address
                )

            # If "subnet_id" is defined, we know the instance belongs to a
            # VPC. Handle the security group differently.
            primary_nic = NetworkInterfaceSpecification(
                subnet_id=subnet_id,
                groups=configDict.get('securitygroup'),
                associate_public_ip_address=configDict[
                    'associate_public_ip_address'],
                private_ip_address=private_ip_address,
            )

            args['network_interfaces'] = \
                NetworkInterfaceCollection(primary_nic)
        else:
            # Default instance (non-VPC)
            args['security_groups'] = configDict.get('securitygroup', [])

        return args

    def __get_common_launch_args3(
            self, conn3: ServiceResource, configDict: Dict[str, Any],
            node: Optional[Node] = None, *,
            addNodesRequest: Optional[dict] = None,
            insertnode_request: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Return key-value pairs of arguments for passing to launch API
        """
        args = {
            'KeyName': configDict['keypair'],
            'InstanceType': configDict['instancetype'],
        }

        # Set up placement dict
        placement = {}
        value = configDict.get('zone')
        if value is not None:
            placement['AvailabilityZone'] = value

        value = configDict.get('placementgroup')
        if value is not None:
            placement['GroupName'] = value

        # Add to args
        if placement:
            args['Placement'] = placement

        # User data
        if configDict['cloud_init']:
            args['UserData'] = self.__get_user_data(
                configDict,
                node=node,
                insertnode_request=insertnode_request
            )

        # Kernel ID
        if 'aki' in configDict and configDict['aki']:
            # Override kernel used for new instances
            args['KernelId'] = configDict['aki']

        # Ramdisk ID
        if 'ari' in configDict and configDict['ari']:
            # Override ramdisk used for new instances
            args['RamdiskId'] = configDict['ari']

        # Build 'BlockDeviceMappings'
        bdms = self.__build_block_device_map(
            conn3,
            configDict['block_device_map']
            if 'block_device_map' in configDict else None,
            configDict['ami']
        )
        # bdms is a boto.ec2.blockdevicemapping.BlockDeviceMapping
        # We need to translate it to a list of dicts for boto3
        args['BlockDeviceMappings'] = \
            translate_blockdevicemappings_for_boto3(bdms)

        if 'ebs_optimized' in configDict:
            args['EbsOptimized'] = configDict['ebs_optimized']

        if 'monitoring_enabled' in configDict:
            args['Monitoring'] = {'Enabled': configDict['monitoring_enabled']}

        if 'iam_instance_profile_name' in configDict and \
                configDict['iam_instance_profile_name']:
            args['IamInstanceProfile'] = \
                {'Name': configDict['iam_instance_profile_name']}

        if 'subnet_id' in configDict and \
                configDict['subnet_id'] is not None:
            subnet_id = configDict['subnet_id']

            # If "subnet_id" is defined, we know the instance belongs to a
            # VPC. Handle the security group differently.
            primary_nic = {
                'AssociatePublicIpAddress': \
                    configDict['associate_public_ip_address'],
                'Groups': configDict.get('securitygroup', []),
                'SubnetId': subnet_id,
                'DeviceIndex': 0,  # AWS docs: primary NIC = device index of 0
            }

            # Handle private IP address
            private_ip_address = get_private_ip_address_argument(
                addNodesRequest
            ) if addNodesRequest else None

            if private_ip_address:
                self._logger.debug(
                    'Assigning ip address [%s] to new instance',
                    private_ip_address
                )
                primary_nic['PrivateIpAddress'] = private_ip_address

            args['NetworkInterfaces'] = [primary_nic]
        else:
            # Default instance (non-VPC)
            args['SecurityGroupIds'] = configDict.get('securitygroup', [])

        # Get tags and convert to format expected by boto3
        tags = self.__get_tags_for_instance_creation(
            configDict,
            node=node,
            addNodesRequest=addNodesRequest
        )
        tag_dict_list = [{'Key': k, 'Value': v} for k, v in tags.items()]

        # Set up a list of "tag specification dicts"
        tag_specifications = [
            {
                'ResourceType': 'instance',
                'Tags': tag_dict_list,
            },
            {
                'ResourceType': 'volume',
                'Tags': tag_dict_list,
            },
        ]

        # Add full tag specifications to args
        args['TagSpecifications'] = tag_specifications

        return args

    def __launchEC2(self, conn3: EC2Connection, configDict: Dict[str, Any],
                    *, count: int = 1, node: Optional[Node] = None,
                    addNodesRequest: Optional[dict] = None):
        """
        Launch EC2 instances. If 'node' is specified, Tortuga node
        record exists at time of instance creation.

        Note that conn3 is a boto3 connection to EC2.

        :raises CommandFailed:
        """

        self._validate_ec2_launch_args(conn3, configDict)

        runArgs = self.__get_common_launch_args3(
            conn3,
            configDict,
            node=node,
            addNodesRequest=addNodesRequest
        )

        try:
            return conn3.create_instances(
                ImageId=configDict['ami'],
                MinCount=1,
                MaxCount=count,
                **runArgs
            )
        except botocore.exceptions.ClientError as ex:
            raise CommandFailed(f'AWS error: {ex}')

    def __build_block_device_map(self,
                                 conn: Union[EC2Connection, ServiceResource],
                                 block_device_map, image_id: str):
        result = None

        if block_device_map:
            # Use block device mapping from adapter configuration
            self._logger.debug(
                'Setting \'block_device_map\' argument to [%s]' % (
                    block_device_map))

            result = block_device_map

        is_boto3_conn = isinstance(conn, ServiceResource)
        if is_boto3_conn:
            ami = conn.Image(image_id)
            block_devices = \
                [bdm['DeviceName'] for bdm in ami.block_device_mappings]
        else:
            ami = conn.get_image(image_id)
            block_devices = list(ami.block_device_mapping)

        # determine root device name
        root_block_devices = ec2_get_root_block_devices(block_devices)

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
            self._logger.warning(
                'Unable to determine root device name for'
                ' AMI [%s]' % (ami.id))

            self._logger.warning(
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

            self._logger.debug(logmsg)

        return result

    def stop(self, hardwareProfileName, deviceName):
        """
        Stops addhost daemon from creating additional nodes.

        """
        pass

    def get_initial_tags(self, config: Dict[str, str], hwp_name: str,
                         swp_name: str, node: Optional[Node] = None) \
            -> Dict[str, str]:
        """
        Returns the list of tags that should be applied to one or more
        nodes upon creation.  We override the base class version of this
        method to properly handle the case where the user overrides the
        automatically-detected installer IP address.

        :param Dict[str, str] config: the resource adapter profile config
        :param str hwp_name:          the node hardware profile name
        :param str swp_name:          the node software profile name

        :return Dict[str, str: the tags that should be applied
        """
        # Get default initial tags
        tags = super().get_initial_tags(config, hwp_name, swp_name)

        installer_ip = config.get('installer_ip', None)
        if installer_ip is not None:
            tags['tortuga-installer_ipaddress'] = \
                self._sanitze_tag_value(installer_ip)

        # Get name tag
        name_tag = self._get_name_tag(config, node=node)
        if name_tag:
            tags['Name'] = name_tag

        # Patch managed tags
        tags = patch_managed_tags(tags)

        return tags

    def __get_tags_for_instance_creation(self, configDict: Dict[str, Any],
                                         node: Optional[Node] = None,
                                         addNodesRequest: Optional[dict] = None
            ) -> Dict[str, Any]:
        """
        Generates a dict of tags to be applied to an EC2 instance at creation.
        """
        # Check that we have one of either node or addNodesRequest to get
        # hardware/software profile names from
        if not (node or addNodesRequest):
            err_msg = 'Must provide either \'node\' or \'addNodesRequest\''
            self._logger.exception('Error getting tags for instance: '
                                   f'{err_msg}')
            raise InvalidArgument(err_msg)

        # Hardware/software profiles names come from either node object
        # or addNodesRequest
        hwp_name = node.hardwareprofile.name if node is not None \
            else addNodesRequest['hardwareProfile']
        swp_name = node.softwareprofile.name if node is not None \
            else addNodesRequest['softwareProfile']

        # Compile tags
        tags = self.get_initial_tags(configDict, hwp_name, swp_name, node=node)

        return tags

    def _get_name_tag(self, config: dict, node: Optional[Node] = None) -> str:
        name_tag = None
        if config['use_instance_hostname']:
            if 'Name' not in config.get('tags', {}):
                name_tag = 'Tortuga compute node'
        elif node and node.name:
            name_tag = node.name

        return name_tag

    def _tag_instance(self, config: dict, conn: EC2Connection,
                      node: Node, instance, tags: Dict[str, str] = {}):
        """
        Add tags to a VM instance and attached EBS volumes

        :param dict config:        the resource adapter configuration
        :param EC2Connection conn: a configured EC2 connection
        :param Node node:          the database node instance
        :param instance:           the EC2 instance to tag
        :param tags:               optional dict of tags to apply; if not
                                   provided, default tags are used

        """
        self._logger.debug(
            'Assigning tags to instance: {}'.format(instance.id))

        # If a dict of tags is not provided, get default tags
        if not tags:
            tags = self.get_initial_tags(config, node.hardwareprofile.name,
                                         node.softwareprofile.name, node=node)

        self._tag_resources(conn, [instance.id], tags)
        self._tag_ebs_volumes(conn, instance, tags)

    def _tag_resources(self, conn: EC2Connection, resource_ids: List[str],
                       tags: Dict[str, str], replace: bool = False) -> None:
        """
        Tag a list of AWS resources.

        :param EC2Connection conn:     a configured EC2 connection
        :param List[str] resource_ids: the list of resources to tag
        :param Dict[str, str] tags:    the tags to attach to the resources

        """
        self._logger.debug('Adding tags to resources: {}'.format(
            ' '.join(resource_ids)))

        conn.create_tags(resource_ids, tags)

    def _tag_ebs_volumes(self, conn: EC2Connection, instance,
                         tags: Dict[str, str]) -> None:
        """
        Tag EBS volumes attached to an instance.

        :param EC2Connection conn:  a configured EC2 connection
        :param instance:            the EC2 instance to tag
        :param Dict[str, str] tags: the tags to attach to the resources

        """
        #
        # Get list of all EBS volumes associated with instance
        #
        resource_ids = [
            bdm.volume_id
            for bdm in instance.block_device_mapping.values()
            if bdm.volume_id
        ]

        self._tag_resources(conn, resource_ids, tags)

    def __common_prelaunch(self, launch_request: LaunchRequest):
        """
        Write log entries about node launch request
        """

        count = launch_request.addNodesRequest['count']

        logmsg = 'Launching 1 instance' if count == 1 else \
            f'Launching {count} instances'

        self._logger.info(logmsg)

        if 'user_data_script_template' in launch_request.configDict:
            self._logger.info(
                'Using user-data script template [%s]' % (
                    launch_request.configDict['user_data_script_template']))
        elif 'cloud_init_script_template' in launch_request.configDict:
            self._logger.info(
                'Using cloud-init script template [%s]' % (
                    launch_request.configDict['cloud_init_script_template']))

        if 'securitygroup' not in launch_request.configDict or \
                not launch_request.configDict['securitygroup']:
            self._logger.warning(
                '\'securitygroup\' not configured. Default security group'
                ' will be used, which may not be desired behaviour'
            )

    def deleteNode(self, nodes: List[Node]) -> None:
        self._logger.debug(
            'Deleting nodes: [{}]'.format(
                ' '.join([node.name for node in nodes]))
        )

        for node in nodes:
            self.__delete_node(node)

    def __delete_node(self, node: Node) -> None:
        """
        Terminate instance associated with node
        """

        if not node.instance or not node.instance.instance:
            # this really shouldn't ever happen. Nodes with backing AWS
            # instances should never not have an associated instance

            self._logger.warning(
                'Unable to determine AWS instance associated with'
                ' node [{0}]; instance may still be running!'.format(
                    node.name))

            return

        self._logger.info(
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
            self._logger.warning(
                'Error while terminating instance [{0}]: {1}'.format(
                    node.instance.instance, exc.message
                )
            )

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

        self._logger.debug(
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

                self._logger.warning(
                    'startupNode(): node [%s] has no corresponding AWS'
                    ' instance' % (node.name))

                continue

            try:
                if instance.state != 'running':
                    instance.start()

                    self._logger.info(
                        'Node [%s] (instance [%s]) started' % (
                            node.name, instance.id))
            except boto.exception.EC2ResponseError as exc:
                # Ignore any errors from EC2
                msg = 'Error starting node [%s] (instance [%s]): %s (%s)' % (
                    node.name, instance.id, exc.message, exc.error_code)

                self._logger.warning(msg)

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
        self._logger.debug(
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
                self._logger.warning(
                    'rebootNode(): node [%s] has no associated'
                    ' instance' % (node.name))

                continue

            self._logger.debug(
                'rebootNode(): instance=[%s]' % (instance.id))

            try:
                instance.reboot()
            except boto.exception.EC2ResponseError as exc:
                # Ignore any errors from EC2
                msg = 'Error rebooting node [%s] (instance [%s]): %s (%s)' % (
                    node.name, instance.id, exc.message, exc.error_code)

                self._logger.warning(msg)

                continue

            self._logger.info(
                'Node [%s] (instance [%s]) rebooted' % (
                    node.name, instance.id))

    def shutdownNode(self, nodes: List[Node],
                     bSoftReset: Optional[bool] = False) -> None:
        self._logger.debug(
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

            self._logger.debug(
                'shutdownNode(): instance=[%s]' % (instance.id))

            try:
                instance.stop(force=not bSoftReset)

                self._logger.info(
                    'Node [%s] (instance [%s]) shutdown' % (
                        node.name, instance.id))
            except boto.exception.EC2ResponseError as exc:
                # Ignore any errors from EC2
                msg = ('Error shutting down node [%s] (instance [%s]):'
                       ' %s (%s)' % (
                           node.name, instance.id, exc.message,
                           exc.error_code))

                self._logger.warning(msg)

                continue

    def updateNode(self, session: Session, node: Node,
                   updateNodeRequest: dict) -> None: \
            # pylint: disable=unused-argument
        self._logger.debug(
            'updateNode(): node=[{0}]'.format(node.name))

        addNodesRequest = {}

        addNodesRequest['resource_adapter_configuration'] = \
            node.instance.resource_adapter_configuration.name

        if node.state == state.NODE_STATE_ALLOCATED and \
                'state' in updateNodeRequest and \
                updateNodeRequest['state'] != 'Allocated':
            # Node state transitioning from 'Allocated'

            self._logger.debug(
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
                self._logger.debug(
                    'updateNode(): node=[{0}] updating'
                    ' network'.format(node.name))

                self._pre_add_host(
                    node.name,
                    node.hardwareprofile.name,
                    node.softwareprofile.name,
                    prov_nic.ip)

        configDict = self.get_config(
            addNodesRequest['resource_adapter_configuration'])

        # Get connection to AWS
        conn = self.getEC2Connection(configDict)

        instance_id = updateNodeRequest['metadata']['ec2_instance_id']

        instance = self.__get_instance_by_instance_id(conn, instance_id)

        self._tag_instance(configDict, conn, node, instance)

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

        try:
            configDict = self.get_node_resource_adapter_config(
                NodesDbHandler().getNode(self.session, name)
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

        self._logger.debug(
            'get_instance_size_mapping(instancetype=[%s])', value)

        fn = os.path.join(self._cm.getKitConfigBase(), 'aws-instances.csv')
        if not os.path.exists(fn):
            return vcpus

        with open(fn) as fp:
            dr = csv.DictReader(fp)

            for entry in dr:
                if 'API Name' not in entry or 'vCPUs' not in entry:
                    # Skip possibility of malformed entry
                    continue

                if entry['API Name'] != value:
                    continue

                self._logger.debug(
                    'get_instance_size_mapping() cache hit')

                # Found matching entry
                vcpus = int(entry['vCPUs'].split(' ', 1)[0])

                break
            else:
                self._logger.debug(
                    'get_instance_size_mapping() cache miss')

        return vcpus

    def set_node_tag(self, node: Node, tag_name: str, tag_value: str):
        config = self.get_node_resource_adapter_config(node)
        conn = self.getEC2Connection(config)
        instance_id = node.instance.instance
        conn.create_tags([instance_id], {tag_name: tag_value})

    def unset_node_tag(self, node: Node, tag_name: str):
        config = self.get_node_resource_adapter_config(node)
        conn = self.getEC2Connection(config)
        instance_id = node.instance.instance
        conn.delete_tags([instance_id], [tag_name])

    def cloudserveraction_stop(self, cloudconnectorprofile_id: str,
                               cloudserver_id: str, **kwargs):
        force = kwargs.get("force", False)
        cfg = self.get_config(cloudconnectorprofile_id)
        conn = self.getEC2Connection(cfg)
        instance_id = self._get_instance_id_from_cloudserver_id(
            cloudserver_id)
        instance = self.__get_instance_by_instance_id(conn, instance_id)
        instance.stop(force=force)

    def cloudserveraction_start(self, cloudconnectorprofile_id: str,
                                cloudserver_id: str, **kwargs):
        cfg = self.get_config(cloudconnectorprofile_id)
        conn = self.getEC2Connection(cfg)
        instance_id = self._get_instance_id_from_cloudserver_id(
            cloudserver_id)
        instance = self.__get_instance_by_instance_id(conn, instance_id)
        instance.start()

    def cloudserveraction_restart(self, cloudconnectorprofile_id: str,
                                  cloudserver_id: str, **kwargs):
        cfg = self.get_config(cloudconnectorprofile_id)
        conn = self.getEC2Connection(cfg)
        instance_id = self._get_instance_id_from_cloudserver_id(
            cloudserver_id)
        instance = self.__get_instance_by_instance_id(conn, instance_id)
        instance.reboot()

    def cloudserveraction_delete(self, cloudconnectorprofile_id: str,
                                 cloudserver_id: str, **kwargs):
        cfg = self.get_config(cloudconnectorprofile_id)
        conn = self.getEC2Connection(cfg)
        instance_id = self._get_instance_id_from_cloudserver_id(
            cloudserver_id)
        conn.terminate_instances([instance_id])

    def _get_instance_id_from_cloudserver_id(self, cloudserver_id) -> str:
        #
        # cloud server IDs for AWS are in the form of aws:<instance-id>
        #
        id_parts = cloudserver_id.split(':')
        if len(id_parts) != 2:
            raise Exception("Invalid cloud server id")
        if id_parts[0].lower() != self.__adaptername__.lower():
            raise Exception("Resource adapter mismatch")
        return id_parts[1]


def get_primary_nic(nics: List[Nic]) -> Nic:
    result = [nic for nic in nics if nic.boot]

    if not result:
        raise NicNotFound('Provisioning nic not found')

    return result[0]


def get_private_ip_address_argument(addNodesRequest: Dict[str, Any]) \
        -> Optional[str]:
    """
    Parse ip address argument from addNodesRequest
    """

    private_ip_address = None
    if addNodesRequest and addNodesRequest['count'] == 1 and \
            'nodeDetails' in addNodesRequest:
        node_spec = addNodesRequest['nodeDetails'][0]

        if 'nics' in node_spec and \
                node_spec['nics'] and \
                'ip' in node_spec['nics'][0]:
            private_ip_address = node_spec['nics'][0]['ip']

    return private_ip_address


def translate_blockdevicemappings_for_boto3(
        block_device_mapping: BlockDeviceMapping) -> List[Dict]:
    """
    Translate block device mappings from
    boto.ec2.blockdevicemapping.BlockDeviceMapping (effectively a dict of
    boto.ec2.blockdevicemapping.BlockDeviceType objects) into a list
    of dicts, where each dict describes a block device
    """
    ebs_attr_map = {
        'snapshot_id': 'SnapshotId',
        'delete_on_termination': 'DeleteOnTermination',
        'volume_type': 'VolumeType',
        'iops': 'Iops',
        'encrypted': 'Encrypted',
    }

    block_device_list = []
    for device_name, bdt in block_device_mapping.items():

        # Root-level attributes
        bd_dict = {'DeviceName': device_name}
        no_device = getattr(bdt, 'no_device', False)
        if no_device:
            bd_dict['NoDevice'] = no_device

        # Nested EBS attributes
        ebs_dict = {}
        for boto_attr, boto3_key in ebs_attr_map.items():
            value = getattr(bdt, boto_attr)
            if value is not None:
                ebs_dict[boto3_key] = value
        # Do this one manually for type conversion
        if bdt.size is not None:
            ebs_dict['VolumeSize'] = int(bdt.size)

        if ebs_dict:
            bd_dict['Ebs'] = ebs_dict

        # Append to list of block devices
        block_device_list.append(bd_dict)

    return block_device_list

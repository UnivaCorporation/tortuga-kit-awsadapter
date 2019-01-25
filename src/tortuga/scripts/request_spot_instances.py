#!/usr/bin/env python

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

import datetime
from typing import Optional
import boto3
import sys
from tortuga.cli.tortugaCli import TortugaCli
from tortuga.exceptions.invalidArgument import InvalidArgument
from tortuga.wsapi.addHostWsApi import AddHostWsApi
from tortuga.wsapi.hardwareProfileWsApi import HardwareProfileWsApi
from .spot_common import SpotInstanceCommonMixin


class RequestSpotInstancesCLI(TortugaCli, SpotInstanceCommonMixin):
    """Application class for wrapper for request-spot-instances"""

    def parseArgs(self, usage=None):
        self.addOption(
            '--software-profile', metavar='NAME', required=True,
            help='Associate new nodes with given software profile'
        )

        self.addOption(
            '--hardware-profile', metavar='NAME', required=True,
            help='Add new nodes based on this hardware profile'
        )

        self.addOption(
            '--count', '-n', dest='count', metavar='COUNT',
            type=int, default=1,
            help='Specify number of spot instances to request'
        )

        self.addOption(
            '--price', type=float,
            help='Hourly spot instance price (in dollars)'
        )

        self.addOption(
            '--resource-adapter-configuration', '-A',
            metavar='NAME',
            help='Specify resource adapter configuration for operation.'
                 ' Note: this overrides the default resource adapter'
                 ' configuration set on the hardware profile.'
        )

        self.addOption(
            '--assume-yes', '--yes', dest='assume_yes',
            help='When making spot instance requests without specifying the'
                 ' price, skip confirmation prompt',
            action='store_true',
            default=False
        )

        super(RequestSpotInstancesCLI, self).parseArgs(usage=usage)

    def runCommand(self):
        self.parseArgs()

        adapter_cfg = self.__get_adapter_cfg(
            self.getArgs().resource_adapter_configuration
        )

        instance_type: Optional[str] = \
            self._get_adapter_cfg_key(adapter_cfg, 'instancetype')
        if instance_type is None:
            raise InvalidArgument(
                'Instance type is not configured; unable to proceed'
            )

        if self.getArgs().price is None:
            price = self._get_current_spot_price(adapter_cfg)

            if not self.getArgs().assume_yes:
                print(
                    'Do you wish to request {} {} spot instance(s) @ ${}/hour'
                    ' [N/y]? '.format(
                        self.getArgs().count, instance_type, price
                    ),
                    end=''
                )

                response = input()
                if not response or response.lower().startswith('n'):
                    print('Operation aborted by user!')
                    sys.exit(1)
            else:
                print(
                    'Requesting {} {} spot instance(s) at current price:'
                    ' ${}/hour'.format(
                        self.getArgs().count, instance_type, price
                    )
                )
        else:
            price = self.getArgs().price

            print('Requesting {} {} spot instance(s) @ ${}/hour'.format(
                self.getArgs().count, instance_type, price)
            )

        addNodesRequest = {
            'count': self.getArgs().count,
            'spot_instance_request': {
                'type': 'one-time',
                'price': price,
            },
        }

        if self.getArgs().resource_adapter_configuration:
            addNodesRequest['resource_adapter_configuration'] = \
                self.getArgs().resource_adapter_configuration

        if self.getArgs().software_profile:
            addNodesRequest['softwareProfile'] = \
                self.getArgs().software_profile

        if self.getArgs().hardware_profile:
            addNodesRequest['hardwareProfile'] = \
                self.getArgs().hardware_profile

        AddHostWsApi().addNodes(addNodesRequest)

    def __get_adapter_cfg(self, adapter_cfg_profile: Optional[str]) -> dict:
        if adapter_cfg_profile is None:
            hardwareProfileWsApi = HardwareProfileWsApi(
                    username=self.getUsername(),
                    password=self.getPassword(),
                    baseurl=self.getUrl(),
                    verify=self._verify,
            )

            hardware_profile = hardwareProfileWsApi.getHardwareProfile(
                self.getArgs().hardware_profile,
            )

            value = hardware_profile.getDefaultResourceAdapterConfig()

            adapter_cfg_profile = value if value is not None else 'Default'

        return self._get_adapter_cfg(adapter_cfg_profile)

    def _get_current_spot_price(self, adapter_cfg):
        """
        :raises InvalidArgument:
        """

        instance_type = self._get_adapter_cfg_key(adapter_cfg, 'instancetype')

        subnet_id: Optional[str] = \
            self._get_adapter_cfg_key(adapter_cfg, 'subnet_id')
        if subnet_id is None:
            raise InvalidArgument(
                'subnet_id is not configured; unable to determine zone'
            )

        region = self._get_adapter_cfg_key(adapter_cfg, 'region')

        session = boto3.session.Session(region_name=region)

        conn = session.client('ec2')

        availability_zone = self._get_adapter_cfg_key(adapter_cfg, 'zone')
        if availability_zone is None:
            # Determine availability zone from configured subnet
            response = conn.describe_subnets(
                Filters=[
                    {
                        'Name': 'subnet-id',
                        'Values': [
                            subnet_id,
                        ],
                    },
                ],
            )

            availability_zone = response['Subnets'][0]['AvailabilityZone']

        product_description = 'Linux/UNIX (Amazon VPC)' \
            if subnet_id is not None else 'Linux/UNIX'

        start_time = None
        end_time = None

        now = datetime.datetime.utcnow()

        start_time = now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_time = start_time

        response = conn.describe_spot_price_history(
            AvailabilityZone=availability_zone,
            InstanceTypes=[instance_type],
            ProductDescriptions=[product_description],
            StartTime=start_time, EndTime=end_time,
        )

        return response['SpotPriceHistory'][0]['SpotPrice']


def main():
    RequestSpotInstancesCLI().run()

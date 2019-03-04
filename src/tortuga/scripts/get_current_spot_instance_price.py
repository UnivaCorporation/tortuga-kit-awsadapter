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
import sys
from typing import Optional

import boto3

from .commonSpotInstanceCli import CommonSpotInstanceCLI


class GetCurrentSpotInstancePriceCLI(CommonSpotInstanceCLI):
    def parseArgs(self, usage=None):
        self.addOption(
            '--resource-adapter-configuration', '-A',
            default='Default', metavar='<value>',
            help='Specify resource adapter configuration for operation')

        self.addOption(
            '--instance-type',
            metavar='INSTANCETYPE',
            help='Override instance type from resource adapter configuration'
                 'profile',
        )

        self.addOption(
            '--availability-zone', metavar='<value>',
            help='Get price for specific availability zone. Use \'all\''
                 ' to get prices for all availability zones')

        super().parseArgs(usage=usage)

    def runCommand(self):
        self.parseArgs()

        self._get_current_spot_price()

    def _get_current_spot_price(self):
        adapter_cfg = self._get_adapter_cfg(
            self.getArgs().resource_adapter_configuration
        )

        region = self._get_adapter_cfg_key(adapter_cfg, 'region')

        session = boto3.session.Session(region_name=region)

        conn = session.client('ec2')

        subnet_id: Optional[str] = \
            self._get_adapter_cfg_key(adapter_cfg, 'subnet_id')
        instance_type: Optional[str] = None

        instance_type: Optional[str] = self.getArgs().instance_type \
            if self.getArgs().instance_type else \
            self._get_adapter_cfg_key(adapter_cfg, 'instancetype')
        if instance_type is None:
            print('Error: instance type is not configured; unable to proceed',
                  file=sys.stderr)

            sys.exit(1)

        if self.getArgs().availability_zone:
            # Command-line overrides configured availability zone
            zone = self.getArgs().availability_zone
        else:
            zone = self._get_adapter_cfg_key(adapter_cfg, 'zone')
            if zone is None:
                # Determine availability zone from configured subnet
                if subnet_id is not None:
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

                    zone = response['Subnets'][0]['AvailabilityZone']
                else:
                    print('Error: subnet_id is not configured; unable to'
                          ' determine zone', file=sys.stderr)

                    sys.exit(1)

        product_description = 'Linux/UNIX (Amazon VPC)' \
            if subnet_id is not None else 'Linux/UNIX'

        start_time = None
        end_time = None

        now = datetime.datetime.utcnow()

        start_time = now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_time = start_time

        if zone == 'all':
            # Query EC2 for all zones in configured region
            zones = [
                zone_['ZoneName']
                for zone_ in
                conn.describe_availability_zones()['AvailabilityZones']
            ]
        else:
            zones = [zone]

        for availability_zone in zones:
            response = conn.describe_spot_price_history(
                AvailabilityZone=availability_zone,
                InstanceTypes=[instance_type],
                ProductDescriptions=[product_description],
                StartTime=start_time, EndTime=end_time,
            )

            for price_history in response['SpotPriceHistory']:
                print(
                    availability_zone, price_history['InstanceType'],
                    price_history['SpotPrice'],
                    price_history['ProductDescription']
                )


def main():
    GetCurrentSpotInstancePriceCLI().run()

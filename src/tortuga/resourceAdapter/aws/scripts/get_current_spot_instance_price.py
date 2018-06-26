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

import boto.vpc

from tortuga.cli.tortugaCli import TortugaCli
from tortuga.resourceAdapter.aws import Aws


class AppClass(TortugaCli):
    def __init__(self):
        super(AppClass, self).__init__()

    def parseArgs(self, usage=None):
        self.addOption(
            '--resource-adapter-configuration', '-A',
            default='default', metavar='<value>',
            help='Specify resource adapter configuration for operation')

        self.addOption(
            '--availability-zone', metavar='<value>',
            help='Get price for specific availability zone. Use \'all\''
                 ' to get prices for all availability zones')

        super(AppClass, self).parseArgs(usage=usage)

    def runCommand(self):
        self.parseArgs()

        adapter = Aws()

        configDict = adapter.getResourceAdapterConfig(
            self.getOptions().resource_adapter_configuration)

        conn = adapter.getEC2Connection(configDict)

        vpc_conn = boto.vpc.VPCConnection()

        if self.getOptions().availability_zone:
            # Command-line overrides configured availability zone
            zone = self.getOptions().availability_zone
        elif 'zone' not in configDict or not configDict['zone']:
            # Determine availability zone from configured subnet
            if 'subnet_id' in configDict:
                vpc_subnet = vpc_conn.get_all_subnets(
                    subnet_ids=[configDict['subnet_id']])

                zone = vpc_subnet[0].availability_zone
            else:
                zone = None
        else:
            zone = configDict['zone']

        product_description = 'Linux/UNIX (Amazon VPC)' \
            if 'subnet_id' in configDict else 'Linux/UNIX'

        start_time = None
        end_time = None

        now = datetime.datetime.utcnow()

        start_time = now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_time = start_time

        if zone == 'all':
            # Query EC2 for all zones in configured region
            zones = [zone_.name for zone_ in conn.get_all_zones()]
        else:
            zones = [zone]

        for availability_zone in zones:
            for spot_price in conn.get_spot_price_history(
                    instance_type=configDict['instancetype'],
                    product_description=product_description,
                    start_time=start_time, end_time=end_time,
                    availability_zone=availability_zone):
                print(availability_zone, spot_price.instance_type,
                      spot_price.price,
                      spot_price.product_description)


def main():
    AppClass().run()

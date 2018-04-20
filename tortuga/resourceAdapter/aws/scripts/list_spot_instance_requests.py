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

"""
List spot instance requests *KNOWN* to Tortuga. This is not a replacement
for 'aws ec2 describe-spot-instance-requests'
"""

import configparser
import os.path
import sys

import boto3

from tortuga.cli.tortugaCli import TortugaCli
from tortuga.config.configManager import ConfigManager
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
            '--verbose', action='store_true', default=False,
            help='Enable verbose output')

        super(AppClass, self).parseArgs(usage=usage)

    def runCommand(self):
        self.parseArgs()

        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(ConfigManager().getRoot(), 'var',
                              'spot-instances.conf'))

        if not cfg.sections():
            sys.exit(0)

        adapter = Aws()
        adapter_cfg = adapter.getResourceAdapterConfig(
            self.getOptions().resource_adapter_configuration)

        session = boto3.session.Session(region_name=adapter_cfg['region'].name)

        ec2_conn = session.client('ec2')

        result = ec2_conn.describe_spot_instance_requests(
            SpotInstanceRequestIds=cfg.sections())

        for sir in result[u'SpotInstanceRequests']:
            node = cfg.get(sir[u'SpotInstanceRequestId'], 'node') \
                if cfg.has_option(sir[u'SpotInstanceRequestId'], 'node') else \
                None

            if not node:
                print('{0} {1} {2}'.format(
                    sir['SpotInstanceRequestId'],
                    sir[u'State'], sir[u'Status'][u'Code']))
            else:
                node_label = node \
                    if node != '<unknown>' and self.getOptions().verbose else \
                    node.split('.', 1)[0]

                print('{0} ({3}) {1} {2}'.format(
                    sir[u'SpotInstanceRequestId'],
                    sir[u'State'], sir[u'Status'][u'Code'], node_label))


def main():
    AppClass().run()

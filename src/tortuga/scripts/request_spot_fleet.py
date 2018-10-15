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
import sys

from tortuga.cli.tortugaCli import TortugaCli
from tortuga.wsapi.addHostWsApi import AddHostWsApi


class RequestSpotFleetCLI(TortugaCli):
    """Application class for wrapper for request-spot-instances"""

    def parseArgs(self, usage=None):
        self.addOption('--software-profile', metavar='NAME')
        self.addOption('--hardware-profile', metavar='NAME')
        self.addOption('--count', '-n', dest='count', metavar='COUNT',
                       type=int, default=1)
        self.addOption('--price', type=float, default=0)
        self.addOption('--resource-adapter-configuration', '-A')

        super(RequestSpotFleetCLI, self).parseArgs(usage=usage)

    def runCommand(self):
        self.parseArgs()

        if not self.getArgs().software_profile or \
                not self.getArgs().hardware_profile:
            print('Instances fulfilled from spot requests without associated'
                  ' hardware and/or software profile will *not* join the'
                  ' cluster. Do you wish to proceed [N/y]? '),

            result = input('')
            if not result or result.lower().startswith('n'):
                sys.exit(1)

        addNodesRequest = dict()

        if self.getArgs().resource_adapter_configuration:
            addNodesRequest['resource_adapter_configuration'] = \
                self.getArgs().resource_adapter_configuration

        if self.getArgs().software_profile:
            addNodesRequest['softwareProfile'] = \
                self.getArgs().software_profile

        if self.getArgs().hardware_profile:
            addNodesRequest['hardwareProfile'] = \
                self.getArgs().hardware_profile

        addNodesRequest['count'] = self.getArgs().count

        spot_fleet_request = dict(type='one-time')

        spot_fleet_request['price'] = self.getArgs().price

        print('Requesting {0} node(s) in software profile [{1}],'
              ' hardware profile [{2}]'.format(
                  self.getArgs().count,
                  self.getArgs().software_profile,
                  self.getArgs().hardware_profile))

        addNodesRequest['spot_fleet_request'] = spot_fleet_request

        AddHostWsApi().addNodes(addNodesRequest)


def main():
    RequestSpotFleetCLI().run()
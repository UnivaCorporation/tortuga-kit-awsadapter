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


import sys
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from .commonSpotInstanceCli import CommonSpotInstanceCLI


class ListSpotInstanceRequestCLI(CommonSpotInstanceCLI):
    def parseArgs(self, usage=None):
        self.addOption(
            '--resource-adapter-configuration', '-A',
            default='Default', metavar='<value>',
            help='Specify resource adapter configuration for operation'
        )

        self.addOption(
            '--verbose', action='store_true', default=False,
            help='Enable verbose output'
        )

        super().parseArgs(usage=usage)

    def runCommand(self):
        self.parseArgs()

        adapter_cfg = self._get_adapter_cfg(
            self.getArgs().resource_adapter_configuration
        )

        region = self._get_adapter_cfg_key(adapter_cfg, 'region')
        if region is None:
            print(
                'Error: unable to determine AWS region for resource adapter'
                ' configuration [{}]'.format(
                    self.getArgs().resource_adapter_configuration),
                file=sys.stderr
            )

            sys.exit(1)

        # call EC2 to get spot instance request state
        ec2_conn = boto3.session.Session(region_name=region).client('ec2')

        for sir_id, sir_metadata, name in self._iter_spot_instance_requests(
                    self.getArgs().resource_adapter_configuration
                ):
            try:
                result = ec2_conn.describe_spot_instance_requests(
                    SpotInstanceRequestIds=[sir_id]
                )

                self.__display_spot_instance_request(
                    result['SpotInstanceRequests'][0],
                    sir_id,
                    name,
                )
            except ClientError as exc:
                if 'Error' in exc.response:
                    if exc.response['Error']['Code'] == \
                            'InvalidSpotInstanceRequestID.NotFound':
                        print(
                                exc.response['Error']['Message'],
                                file=sys.stderr
                        )

    def __display_spot_instance_request(
                self, sir, t_id: str, name: Optional[str]
            ) -> None:
        """
        Output spot instance request id, state, status code, and (optional)
        the associated node name.
        """
        if not name:
            print('{0} {1} {2}'.format(
                sir['SpotInstanceRequestId'],
                sir[u'State'], sir[u'Status'][u'Code']))

            return

        print('{0} ({3}) {1} {2}'.format(
            sir[u'SpotInstanceRequestId'],
            sir[u'State'], sir[u'Status'][u'Code'],
            name)
        )


def main():
    ListSpotInstanceRequestCLI().run()

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

from typing import Dict, List, Optional, Tuple

import boto3
from tortuga.wsapi.nodeWsApi import NodeWsApi

# from .spot_common import SpotInstanceCommonMixin
from .commonSpotInstanceCli import CommonSpotInstanceCLI


class CancelSpotInstanceRequestsCLI(CommonSpotInstanceCLI):
    def parseArgs(self, usage: Optional[str] = None):
        parser = self.getParser()

        mutex = parser.add_mutually_exclusive_group(required=True)

        mutex.add_argument(
            '--all', action='store_true', default=False,
            help='Cancel all spot instance requests managed by Tortuga'
        )

        mutex.add_argument(
            'spot-instance-request-id', nargs='?',
            help='Spot instance request id to cancel'
        )

        parser.add_argument(
            '--terminate', action='store_true', default=False,
            help='Terminate associated instance(s).'
        )

        super(CancelSpotInstanceRequestsCLI, self).parseArgs(usage=usage)

    def runCommand(self):
        self.parseArgs()

        # get all spot instance requests
        if self.getArgs().all:
            sir_tuples = [
                sir_tuple
                for sir_tuple in self._iter_spot_instance_requests()
            ]
        else:
            sir_tuples = [
                self._get_spot_instance_request(
                    getattr(self.getArgs(), 'spot-instance-request-id')
                )
            ]

        self.__cancel_spot_instances(sir_tuples)

    def __cancel_spot_instances(
                self, sir_tuples: List[Tuple[str, dict, Optional[str]]]
            ):
        """
        """


        nodeWsApi = self.configureClient(NodeWsApi)

        ec2_connection_cache: Dict[str, dict] = {}

        for sir_tuple in sir_tuples:
            sir_id, sir_metadata, node = sir_tuple

            adapter_cfg_name = sir_metadata['resource_adapter_configuration']

            adapter_cfg = self._get_adapter_cfg(adapter_cfg_name)

            if adapter_cfg_name not in ec2_connection_cache:
                region_name = self._get_adapter_cfg_key(adapter_cfg, 'region')

                conn_spec = {
                    'ec2_conn': boto3.session.Session(
                        region_name=region_name,
                    ).client('ec2'),
                    'sir_tuples': [sir_tuple]
                }

                ec2_connection_cache[adapter_cfg_name] = conn_spec
            else:
                conn_spec = ec2_connection_cache[adapter_cfg_name]
                conn_spec['sir_tuples'].append(sir_tuple)

        for region_name, conn_spec in ec2_connection_cache.items():
            sir_id_and_name_tuples = [
                (sir_id, name)
                for sir_id, _, name in conn_spec['sir_tuples']
            ]

            print(
                'Cancelling {} spot instance requests'.format(
                      len(sir_id_and_name_tuples)
                )
            )

            ec2_conn = conn_spec['ec2_conn']

            sir_ids = [sir_id for sir_id, _ in sir_id_and_name_tuples]

            response = ec2_conn.describe_spot_instance_requests(
                SpotInstanceRequestIds=sir_ids)

            # Create list of tuples (sir_id, bool) which indicate if the
            # spot instance request should be terminated
            cancelled_spot_instance_requests = []

            for sir in response['SpotInstanceRequests']:
                # All spot instance requests that are 'open' should be
                # terminated to avoid leaving orphaned Tortuga node records
                cancelled_spot_instance_requests.append(
                    sir['SpotInstanceRequestId']
                )

            # TODO: check response here
            ec2_conn.cancel_spot_instance_requests(
                SpotInstanceRequestIds=sir_ids
            )

            for sir_id in sir_ids:
                self.metadataWsApi.deleteMetadata(filter_key=sir_id)

            if not self.getArgs().terminate:
                # '--terminate' flag not specified; continue
                continue

            nodes = [
                name for _, _,
                name in conn_spec['sir_tuples'] if name is not None
            ]

            print('Deleting {} node(s)'.format(len(nodes)))

            nodeWsApi.deleteNode(','.join(nodes))


def main():
    CancelSpotInstanceRequestsCLI().run()

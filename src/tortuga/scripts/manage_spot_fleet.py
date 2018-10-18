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
import boto3
import argparse

from subprocess import check_output

from tortuga.wsapi.addHostWsApi import AddHostWsApi
from ..resourceAdapter.aws.helpers import get_redis_client, get_region


REDIS_CLIENT = get_redis_client()


class ManageSpotFleet():
    """
    Manage spot fleet requests.

    :todo: roll in request_spot_fleet
    """
    def __init__(self, region: str) -> None:
        """
        :param region: String
        :returns: None
        """
        self._key = 'tortuga-aws-splot-fleet-requests'
        self._ec2 = boto3.client(
            'ec2',
            region_name=region
        )

    def create(self,
            hardware_profile: str,
            software_profile: str,
            resource_adapter_configuration: str,
            price: float,
            count: str) -> None:
        """
        Create a spot fleet
        request.

        :param hardware_profile: String
        :param software_profile: String
        :param resource_adapter_configuration: String
        :param price: Float
        :param cost: Integer
        :returns: None
        """
        pass

    def list(self) -> None:
        """
        List the active spot
        fleet requests.

        :returns: None
        """
        for sfr_id in REDIS_CLIENT.hkeys(self._key):
            target: str = REDIS_CLIENT.hget(self._key, sfr_id)
            print(f'ID: {sfr_id.decode()} TARGET: {target.decode()}')

    def set(self, spot_fleet_request_id: str, target: int) -> None:
        """
        Set the target instances
        of a spot fleet request.

        :param spot_fleet_request_id: String
        :param target: Integer
        :returns: None
        """
        self._ec2.modify_spot_fleet_request(
            SpotFleetRequestId=spot_fleet_request_id,
            TargetCapacity=target
        )
        REDIS_CLIENT.hset(
            'tortuga-aws-splot-fleet-requests',
            spot_fleet_request_id,
            target
        )

    def delete(self, spot_fleet_request_id: str) -> None:
        """
        Delete an active
        spot fleet request.

        :param spot_fleet_request_id: String
        :returns: None
        """
        self._ec2.cancel_spot_fleet_requests(
            DryRun=False,
            SpotFleetRequestIds=[
                spot_fleet_request_id,
            ],
            TerminateInstances=True
        )
        REDIS_CLIENT.hdel(
            self._key,
            spot_fleet_request_id
        )


def main():
    parser = argparse.ArgumentParser()

    aws_group = parser.add_argument_group('aws', 'AWS Options')

    aws_group.add_argument(
        '--region',
        default=None,
        help='AWS region to manage Spot Instances in'
    )

    parser.add_argument(
        '-l', '--list',
        action='store_true',
        default=False,
        help='List all active spot fleet requests'
    )

    parser.add_argument(
        '-s', '--set',
        default=None,
        nargs=2,
        metavar='[SPOT FLEET REQUEST ID] [TARGET]',
        help='Set spot fleet request target'
    )

    parser.add_argument(
        '-d', '--delete',
        type=str,
        default=None,
        metavar='[SPOT FLEET REQUEST ID]',
        help='Delete spot fleet request'
    )

    args = parser.parse_args()

    if not args.region:
        args.region = get_region()

    ec2 = boto3.client('ec2', region_name='us-east-1')
    region_check = [region for region in ec2.describe_regions()['Regions']
                if region['RegionName'] == args.region]

    if not region_check:
        print('Error: Invalid EC2 region [{0}] specified\n'.format(args.region))
        sys.exit(1)

    cli = ManageSpotFleet(args.region)

    if args.list:
        cli.list()

    elif args.set:
        cli.set(
            args.set[0],
            int(args.set[1])
        )

    elif args.delete:
        cli.delete(args.delete)


if __name__ == '__main__':
    main()

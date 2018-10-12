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

import json
import logging
import argparse
import sys
import threading
import redis
import boto
import boto.ec2
import boto3

from time import sleep
from daemonize import Daemonize
from subprocess import check_output
from tortuga.exceptions.nodeAlreadyExists import NodeAlreadyExists
from tortuga.wsapi.addHostWsApi import AddHostWsApi


PIDFILE = '/var/log/spotfleetd.pid'

FACTER_PATH = '/opt/puppetlabs/bin/facter'

BACKOFF = {
    'seed': 5,
    'max': 60
}


def get_redis_client():
    try:
        uri = check_output(
            [FACTER_PATH, 'redis_url']
        ).strip().decode()
    except Exception:
        uri = None

    if not uri:
        uri = 'localhost:6379'

    host, port = uri.split(':')

    return redis.StrictRedis(
        host=host,
        port=int(port),
        db=0
    )


REDIS_CLIENT = get_redis_client()


def glide_to_target(spot_fleet_request_id, initial, target, logger,
                    ec2_client) -> None:
    current = initial
    backoff = BACKOFF['seed']
    while current < target:
        try:
            request = ec2_client.describe_spot_fleet_requests(
                SpotFleetRequestIds=[spot_fleet_request_id]
            )['SpotFleetRequestConfigs'][0]
        except Exception as e:
            logger.warning(
                'AWS API error ({}), sleeping for {}'.format(
                    e, backoff))
            sleep(backoff)
            if backoff < BACKOFF['max']:
                backoff *= 2
            if backoff > BACKOFF['max']:
                backoff = BACKOFF['max']
        else:
            backoff = BACKOFF['seed']

        if request['SpotFleetRequestState'] == 'active':
            if (target - current) >= 250:
                current += 250
            else:
                current += (target - current)

            logger.debug(
                'Increasing spot fleet request to {} of {}'.format(
                    current,
                    target
                )
            )

            while True:
                try:
                    ec2_client.modify_spot_fleet_request(
                        SpotFleetRequestId=spot_fleet_request_id,
                        TargetCapacity=current
                    )
                except Exception as e:
                    logger.warning(
                        'AWS API error ({}), sleeping for {}'.format(
                            e, backoff))
                    sleep(backoff)
                    if backoff < BACKOFF['max']:
                        backoff *= 2
                    if backoff > BACKOFF['max']:
                        backoff = BACKOFF['max']
                else:
                    backoff = BACKOFF['max']
                    break

        sleep(5)


def spot_fleet_listener(logger, ec2_client) -> None:
    logger.info('Starting spot fleet listener thread')

    pubsub = REDIS_CLIENT.pubsub()
    pubsub.subscribe('tortuga-aws-spot-fleet-d')

    while True:
        request = pubsub.get_message(timeout=1)

        if request and request['type'] == 'message' and request['data']:
            try:
                data = json.loads(request['data'])
            except Exception:
                continue

            logger.debug('Got fleet request {}'.format(
                data['spot_fleet_request_id']
            ))

            REDIS_CLIENT.set(
                'tortuga-aws-spot-software-profile',
                data['softwareprofile']
            )

            REDIS_CLIENT.set(
                'tortuga-aws-spot-hardware-profile',
                data['hardwareprofile']
            )

            if 'spot_fleet_request_id' in data:
                if data['target'] > 250:
                    glide_thread = threading.Thread(
                        target=glide_to_target,
                        args=(
                            data['spot_fleet_request_id'],
                            250,
                            data['target'],
                            logger,
                            ec2_client
                        ),
                        daemon=True
                    )
                    glide_thread.start()


class FleetSpotdAppClass(object):
    def __init__(self, region: str) -> None:
        self.region = region

        self.logger = None

    def run(self) -> list:
        # Ensure logger is instantiated _after_ process is daemonized
        self.logger = logging.getLogger('tortuga.aws.fleetspotd')

        self.logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        ch = logging.handlers.TimedRotatingFileHandler(
            '/var/log/tortuga_fleetspotd',
            when='midnight'
        )

        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self.logger.addHandler(ch)

        self.logger.info(
            'Starting... EC2 region [{0}]'.format(
                self.region
            )
        )

        boto3_client = boto3.client('ec2', region_name=self.region)

        threads = []

        spot_fleet_thread = threading.Thread(
            target=spot_fleet_listener,
            args=(self.logger, boto3_client),
            daemon=True
        )
        spot_fleet_thread.start()
        threads.append(spot_fleet_thread)

        return [t.join() for t in threads]


def main() -> None:
    parser = argparse.ArgumentParser()

    aws_group = parser.add_argument_group('aws', 'AWS Options')

    aws_group.add_argument(
        '--region',
        default=None,
        help='AWS region to manage Spot Instances in'
    )

    parser.add_argument_group(aws_group)

    parser.add_argument(
        '--verbose',
        action='store_true',
        default=False,
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--daemon',
        action='store_false',
        dest='foreground',
        default=True,
        help='Start awsspotd in the background'
    )

    parser.add_argument(
        '--pidfile',
        default=PIDFILE,
        help='Location of PID file'
    )

    args = parser.parse_args()

    try:
        if not args.region:
            az = check_output(
                [
                    FACTER_PATH,
                    '--no-external-facts',
                    'ec2_metadata.placement.availability-zone'
                ]
            ).strip().decode()

            args.region = az[:-1]

    except Exception:
        args.region = 'us-west-1'

    result_ = [region for region in boto.ec2.regions()
               if region.name == args.region]

    if not result_:
        sys.stderr.write(
            'Error: Invalid EC2 region [{0}] specified\n'.format(
                args.region))
        sys.exit(1)

    cls = FleetSpotdAppClass(args.region)

    daemon = Daemonize(
        app='spotfleetd',
        pid=args.pidfile,
        action=cls.run,
        verbose=args.verbose,
        foreground=args.foreground
    )

    daemon.start()

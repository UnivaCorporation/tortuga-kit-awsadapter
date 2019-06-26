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

import argparse
import asyncio
import json
import logging
import sys
from typing import NoReturn, Optional

import boto
import boto.ec2
from boto.ec2.connection import EC2Connection
from daemonize import Daemonize
from tortuga.exceptions.nodeNotFound import NodeNotFound
from tortuga.wsapi.addHostWsApi import AddHostWsApi
from tortuga.wsapi.metadataWsApi import MetadataWsApi
from tortuga.wsapi.nodeWsApi import NodeWsApi

PIDFILE = '/var/log/awsspotd.pid'

# Poll for spot instance status every 60s
SPOT_INSTANCE_POLLING_INTERVAL = 60


class AWSSpotdAppClass:
    def __init__(self, args, *, logger):
        self.args = args
        self.logger = logger
        self.metadataWsApi = MetadataWsApi()

        self.__bad_requests = []
        self.__bad_request_lock = asyncio.Lock()
        self.__delete_node_list_lock = asyncio.Lock()
        self.__delete_node_list = []

    def run(self):
        self.logger.info('Monitoring EC2 region [%s]', self.args.region)

        loop = asyncio.get_event_loop()

        queue = asyncio.Queue()

        max_tasks = 3

        ec2_conn = boto.ec2.connect_to_region(self.args.region)

        self.logger.debug('Creating %d worker tasks', max_tasks)

        try:
            # create worker coroutines
            tasks = [
                asyncio.ensure_future(
                    self.__worker(f'worker-{i}', queue, ec2_conn)
                ) for i in range(max_tasks)
            ]

            asyncio.ensure_future(self.__poller(queue))

            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.logger.debug('Cancelling worker tasks')

            for task in tasks:
                task.cancel()

            self.logger.debug('Closing asyncio loop')

            loop.close()

    async def __poller(self, queue) -> NoReturn:
        while True:
            self.logger.debug('Polling spot instance requests')

            # TODO: improve filtering to get only keys starting with 'sir-'
            results = self.metadataWsApi.list()
            for result in results:
                if not result['key'].startswith('sir-'):
                    # ignore any unrelated entries
                    # TODO: remove this log message once system has been
                    # validated
                    self.logger.debug(
                        'Ignoring metadata key [%s]',
                        result['key']
                    )

                    continue

                with await self.__bad_request_lock:
                    if result['key'] in self.__bad_requests:
                        self.logger.warning(
                            'Invalid spot instance request [%s] will not be'
                            ' queued', result['key']
                        )

                        continue

                # enqueue spot instance request
                queue.put_nowait(result)

            self.logger.debug('Sleeping for %ds', self.args.polling_interval)

            await asyncio.sleep(self.args.polling_interval)

    async def __worker(self, name: str, queue: asyncio.Queue,
                       ec2_conn: EC2Connection) -> NoReturn:
        self.logger.debug('Worker [%s] initializing...', name)

        while True:
            item = await queue.get()
            try:
                sir_id = item['key']
                spot_instance_request = json.loads(item['value'])
                instance = item['instance']

                self.logger.info(
                    'Worker [%s] processing spot instance request id [%s]',
                    name,
                    sir_id,
                )

                with await self.__bad_request_lock:
                    if sir_id in self.__bad_requests:
                        self.logger.warning(
                            'Ignoring invalid spot instance request: [%s]',
                            sir_id,
                        )

                        continue

                try:
                    await self.process_spot_instance_request(
                        ec2_conn,
                        instance,
                        spot_instance_request,
                    )
                except Exception:
                    self.logger.exception(
                        'Error processing spot instance request [%s]',
                        spot_instance_request,
                    )
            finally:
                queue.task_done()

    async def process_spot_instance_request(
            self,
            ec2_conn: EC2Connection,
            instance: dict,
            spot_instance_request: dict,
            ) -> None:
        """
        :raises EC2ResponseError:
        """

        sir_id = spot_instance_request.get('spot_instance_request_id')
        if sir_id is None:
            with await self.__bad_request_lock:
                self.__bad_requests.append(sir_id)

            return

        try:
            result = ec2_conn.get_all_spot_instance_requests(
                request_ids=[sir_id],
            )
        except boto.exception.EC2ResponseError as exc:
            if exc.status == 400 and \
                    exc.error_code in (
                        'InvalidSpotInstanceRequestID.NotFound',
                    ):
                spot_instance_request['status'] = 'notfound'

            raise

        self.logger.debug(
            'sir: [%s], state: [%s], status code: [%s]',
            sir_id,
            result[0].state,
            result[0].status.code,
        )

        jump_table = {
            'active': self.__handle_active_spot_reqeusts,
            'open': self.__handle_open_spot_requests,
            'closed': self.__handle_closed_spot_requests,
            'cancelled': self.__handle_cancelled_spot_requests,
            'failed': self.__handle_failed_spot_requests,
        }

        handler = jump_table.get(result[0].state)
        if handler is None:
            self.logger.error(
                'Ignoring unknown spot instance request state: [%s]',
                result[0].state
            )

            return

        await handler(
            result[0].status.code,
            sir_id,
            ec2_conn,
            result[0].instance_id,
            instance,
            spot_instance_request
        )

    async def __handle_active_spot_reqeusts(
                self, status_code, sir_id, ec2_conn, instance_id, instance,
                spot_instance_request
            ):
        if status_code != 'fulfilled':
            return

        if instance:
            self.logger.debug(
                'Node [%s] already associated with spot instance'
                ' request [%s]', instance['node']['name'], sir_id
            )

            return

        await self.__fulfilled_request_handler(
            ec2_conn,
            instance_id,
            spot_instance_request,
        )

    async def __handle_open_spot_requests(
                self, status_code, sir_id, ec2_conn,
                instance_id, instance, spot_instance_request
            ):
        """Handle open spot instance requests"""
        if status_code in ('pending-fulfillment', 'price-too-low'):
            return

        if status_code not in (
                    'capacity-oversubscribed',
                    'instance-terminated-by-price',
                    'instance-terminated-no-capacity',
                    'instance-terminated-capacity-oversubscribed',
                    'instance-terminated-launch-group-constraint'
                ):
            # unknown status code
            self.logger.warning(
                'Unrecognized open spot request status code: [%s]',
                status_code
            )

            return

        if status_code == 'capacity-oversubscribed':
            self.logger.info(
                'spot instance request [%s] not fulfilled due to'
                ' oversubscription; request will remain open',
                sir_id,
            )

            return

        self.delete_node(instance)

        spot_instance_request['status'] = 'terminated'

    async def __handle_closed_spot_requests(
                self, status_code, sir_id, ec2_conn,
                instance_id, instance,
                spot_instance_request
            ):
        if status_code == 'marked-for-termination':
            # TODO: any hinting for Tortuga here?
            self.logger.info(
                'Instance [%s] marked for termination', instance_id,
            )

            return

        if status_code == 'system-error':
            self.logger.warning(
                'Reported AWS/EC2 system error for spot instance request id'
                ' [%s]', sir_id)

            return

        if status_code not in (
                    'instance-terminated-by-user',
                    'instance-terminated-by-price',
                    'instance-terminated-no-capacity',
                    'instance-terminated-capacity-oversubscribed',
                    'instance-terminated-launch-group-constraint',
                ):
            # unknown status code
            self.logger.warning(
                'Unrecognized closed spot request status code: [%s]',
                status_code
            )

            return

        await self.delete_node(instance)

        spot_instance_request['status'] = 'terminated'

    async def __handle_cancelled_spot_requests(
                self, status_code, sir_id, ec2_conn,
                instance_id, instance,
                spot_instance_request
            ):
        if status_code == 'canceled-before-fulfillment':
            # TODO: request was cancelled by end-user; nothing to do here

            self.logger.info(
                'Deleting spot instance request id [%s]', sir_id,
            )

            self.metadataWsApi.deleteMetadata(
                filter_key='spot_instance_request_id', filter_value=sir_id
            )

            spot_instance_request['status'] = 'cancelled'

            return

        if status_code == 'request-canceled-and-instance-running':
            # Instance was left running after cancelling spot reqest;
            # nothing to do...
            return

        if status_code in (
                    'instance-terminated-by-user',
                    'instance-terminated-capacity-oversubscribed',
                ):
            await self.delete_node(instance)

            spot_instance_request['status'] = 'terminated'

    async def __handle_failed_spot_requests(
                self, status_code, sir_id, ec2_conn,
                instance_id, instance, spot_instance_request): \
            # pylint: disable=unused-argument
        # TODO: this request is dead in the water; nothing more can happen
        return

    async def __fulfilled_request_handler(
            self,
            ec2_conn: EC2Connection,
            instance_id: str,
            spot_instance_request: dict,
        ):
        """Called when processing valid spot instance request"""

        resvs = ec2_conn.get_all_instances(instance_ids=[instance_id])

        instance = resvs[0].instances[0]

        if instance.state not in ('pending', 'running'):
            self.logger.info(
                'Ignoring instance [%s] in state [%s]',
                instance.id,
                instance.state,
            )

            return

        node_name = instance.private_dns_name

        if spot_instance_request.get('dnsdomain',False):
            node_name = node_name.split(".")[0] + "." + spot_instance_request['dnsdomain']

        self.logger.info(
            'Creating node for spot instance [%s]',
            instance.id,
        )

        # Error: unable to find pre-allocated node record for spot
        # instance request
        addNodesRequest = {
            'softwareProfile':
                spot_instance_request['softwareprofile'],
            'hardwareProfile':
                spot_instance_request['hardwareprofile'],
            'count': 1,
            'nodeDetails': [{
                'metadata': {
                    'ec2_instance_id': instance.id,
                    'ec2_ipaddress': instance.private_ip_address,
                    'spot_instance_request_id': spot_instance_request['spot_instance_request_id'],
                },
            }],
        }

        if 'resource_adapter_configuration' in spot_instance_request:
            addNodesRequest['resource_adapter_configuration'] = \
                spot_instance_request['resource_adapter_configuration']

        if node_name:
            addNodesRequest['nodeDetails'][0]['name'] = node_name

        self.logger.info(
            'Adding node for spot instance request id [%s]',
            spot_instance_request['spot_instance_request_id'],
        )

        await self.__add_node_wrapper(addNodesRequest)

    async def __add_node(self, addNodesRequest):
        self.logger.debug(
            'Add node: addNodesRequest=[%s]',
            addNodesRequest,
        )

        addHostSession = AddHostWsApi().addNodes(addNodesRequest)

        while True:
            response = AddHostWsApi().getStatus(
                session=addHostSession,
                getNodes=True,
            )

            if not response['running']:
                self.logger.debug('response: %s', response)

                # node_name = response['nodes'][0]['name']

                break

            await asyncio.sleep(5)

    async def __add_node_wrapper(self, addNodesRequest: dict):
        try:
            await asyncio.wait_for(
                self.__add_node(addNodesRequest),
                timeout=300.0,
            )
        except asyncio.TimeoutError:
            print('timeout!')

    async def delete_node(self, instance: Optional[dict] = None):
        if not instance:
            # silently ignore the request to delete node
            return

        name = instance['node']['name']

        with await self.__delete_node_list_lock:
            if name in self.__delete_node_list:
                # silently ignore delete request
                return

        self.logger.info('Deleting node [%s]', name)

        try:
            NodeWsApi().deleteNode(name)

            with await self.__delete_node_list_lock:
                self.__delete_node_list.append(name)
        except NodeNotFound:
            with await self.__delete_node_list_lock:
                del self.__delete_node_list[name]


def main():
    parser = argparse.ArgumentParser()

    aws_group = parser.add_argument_group('AWS Options')

    aws_group.add_argument(
        '--region', default='us-east-1',
        help='AWS region to manage Spot Instances in')

    parser.add_argument_group(aws_group)

    parser.add_argument('--verbose', action='store_true', default=False,
                        help='Enable verbose logging')

    parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help='Enable debug output (also enables foreground execution mode)'
    )

    parser.add_argument('--daemon', action='store_false',
                        dest='foreground', default=True,
                        help='Start awsspotd in the background')

    parser.add_argument('--pidfile', default=PIDFILE,
                        help='Location of PID file')

    polling_group = parser.add_argument_group('Polling Options')

    polling_group.add_argument(
        '--polling-interval', '-p', type=int,
        default=SPOT_INSTANCE_POLLING_INTERVAL,
        metavar='SECONDS',
        help='Polling interval (in seconds)',
    )

    parser.add_argument_group(polling_group)

    args = parser.parse_args()

    # Ensure logger is instantiated _after_ process is daemonized
    logger = logging.getLogger('tortuga.aws.awsspotd')

    logger.setLevel(logging.DEBUG)

    if args.debug or args.foreground:
        ch = logging.StreamHandler()
    else:
        # create console handler and set level to debug
        ch = logging.handlers.TimedRotatingFileHandler(
            '/var/log/tortuga_awsspotd', when='midnight')

    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    result_ = [region for region in boto.ec2.regions()
               if region.name == args.region]
    if not result_:
        sys.stderr.write(
            'Error: Invalid EC2 region [{0}] specified\n'.format(
                args.region))
        sys.exit(1)

    klass = AWSSpotdAppClass(args, logger=logger)

    foreground = True if args.debug else args.foreground

    daemon = Daemonize(
        app='awsspotd',
        pid=args.pidfile,
        action=klass.run,
        verbose=args.verbose,
        foreground=foreground,
    )

    daemon.start()

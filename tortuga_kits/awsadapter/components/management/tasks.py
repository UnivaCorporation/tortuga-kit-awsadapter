# Copyright 2008-2020 Univa Corporation
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
App and Task for checking up on AWS Spot Instance Requests
"""

import argparse
import asyncio
import json
import logging
import time
import datetime
import os.path
import configparser
from typing import NoReturn, Optional

import boto
import boto.ec2
from boto.ec2.connection import EC2Connection
from daemonize import Daemonize
import dateutil

from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound

from tortuga.config.configManager import ConfigManager
from tortuga.db.models.node import Node
from tortuga.db.dbManager import DbManager
from tortuga.db.models.instanceMetadata import InstanceMetadata
from tortuga.db.models.instanceMapping import InstanceMapping
from tortuga.resourceAdapter.resourceAdapterFactory import get_api
from tortuga.wsapi.metadataWsApi import MetadataWsApi

PIDFILE = '/var/log/awsspotd.pid'
CONFIG_FILE = 'spot-checker.ini'
CONFIG_SECTION = 'Task'
CONFIG_INTERVAL_SECS = 'interval_seconds'

# Poll for spot instance status every 5m
SPOT_INSTANCE_POLLING_INTERVAL = 60*5
# Expire spot instances after an hour if not up
SPOT_INSTANCE_REGISTER_MAX_WAIT = 60*60


class AWSSpotdAppClass:
    """
    App for checking on  Spot Intance Requests and cleaning up requests
    that don't follow the proper lifecycle.
    """
    def __init__(self, logger, polling_interval=SPOT_INSTANCE_POLLING_INTERVAL,
                 max_register_duration=SPOT_INSTANCE_REGISTER_MAX_WAIT, dbm=None, one_time=False):
        self.logger = logger
        self.metadata_ws_api = MetadataWsApi()
        self.__one_time = one_time
        self.__polling_interval = polling_interval
        self.__max_register_duration = max_register_duration

        if dbm is None:
            self.__dbm = DbManager()
        else:
            self.__dbm = dbm
        self.__done = False
        self.__next_poll = 0
        self.__bad_requests = []
        self.__bad_request_lock = asyncio.Lock()

    def run(self):
        """ Main body of the application.  Read, and optionally continue to read,
        known spot requests and compare against known instances.  """
        loop = asyncio.get_event_loop()

        queue = asyncio.Queue()

        max_tasks = 3

        poller = None
        tasks = []

        self.logger.debug('Creating %d worker tasks', max_tasks)

        try:
            # create worker coroutines
            tasks = [
                asyncio.ensure_future(
                    self.__worker(f'worker-{i}', queue)
                ) for i in range(max_tasks)
            ]

            poller = asyncio.ensure_future(self.__poller(queue, tasks))

            loop.run_until_complete(poller)
        except KeyboardInterrupt:
            pass
        except Exception as ex: # pylint: disable=broad-except
            self.logger.error('Error running event loop: %s', ex)
        finally:
            if not self.__done:
                self.__done = True
                if poller:
                    loop.run_until_complete(poller)

            self.logger.debug('Cancelling worker tasks')
            for task in tasks:
                task.cancel()

            self.logger.debug('Closing asyncio loop')

            self.__dbm.closeSession()

    async def __poller(self, queue, tasks) -> NoReturn:
        resource_adapter = get_api('AWS')
        while not self.__done:
            if self.__next_poll < time.time():
                self.logger.debug('Polling spot instance requests')

                results = self.metadata_ws_api.list()
                resource_adapter.session = self.__dbm.openSession()
                resource_adapter_cfgs = {}
                try:
                    for result in results:
                        if not result['key'].startswith('sir-'):
                            # ignore any unrelated entries
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

                        # Parse the embedded value to get the corresponding
                        # resource adapter configuration
                        value = json.loads(result['value'])
                        # Store the request ID in the value.  This is used by the handlers later on.
                        value['spot_instance_request_id'] = result['key']

                        resource_adapter_cfg = value['resource_adapter_configuration']

                        # Cache resource adapter configurations.
                        # First check if this one has been cached
                        if not resource_adapter_cfg in resource_adapter_cfgs:
                            self.logger.debug(
                                'Loading adapter configuration: [%s]', resource_adapter_cfg)
                            # Get the the configuration for the spot instance request
                            config = resource_adapter.get_config(
                                resource_adapter_cfg)
                            # Save the fields that we may need for other requests in this loop
                            resource_adapter_cfgs[resource_adapter_cfg] = {
                                'cfg': config,
                                'ec2_conn': resource_adapter.getEC2Connection(config),
                                'max_register_duration': config.get('spot_provision_timeout',
                                                                    self.__max_register_duration),
                            }

                        # Update the record to queue to have the appropriate
                        # cached data for the request.
                        result['value'] = value
                        result['ec2_conn'] = resource_adapter_cfgs[resource_adapter_cfg]['ec2_conn']
                        result['max_register_duration'] = \
                            resource_adapter_cfgs[resource_adapter_cfg]['max_register_duration']

                        # enqueue spot instance request
                        queue.put_nowait(result)
                except Exception as ex: # pylint: disable=broad-except
                    self.logger.error(
                        'Unable to poll spot instance requests: %s', ex)
                finally:
                    resource_adapter.session.close()

                if self.__one_time:
                    await queue.join()
                    self.__done = True
                    break
                self.logger.debug('Sleeping for %ds', self.__polling_interval)
                self.__next_poll = time.time() + self.__polling_interval
            await asyncio.sleep(1)
        try:
            for task in tasks:
                await asyncio.wait_for(task, timeout=30.0)
            self.logger.debug('Exiting poller')
        except Exception as ex: # pylint: disable=broad-except
            self.logger.error('Unable to wait for worker tasks: %s', ex)

    async def __worker(self, name: str, queue: asyncio.Queue) -> NoReturn:

        self.logger.debug('Worker [%s] initializing...', name)

        while not self.__done:
            try:
                # Allow other pending co-routines to run
                # await asyncio.sleep(0.0)
                item = queue.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.01)
                continue
            session = self.__dbm.openSession()
            try:
                # Unpack the queued request
                sir_id = item['key']
                spot_instance_request = item['value']
                instance = item['instance']
                ec2_conn = item['ec2_conn']
                max_register_duration = item['max_register_duration']
                node = None

                # Attempt to fetch the node matching the instance in the spot request.
                if instance:
                    if 'id' in instance:
                        try:
                            node = self.__get_node_by_instance(
                                session, instance['instance'])
                        except Exception as ex: # pylint: disable=broad-except
                            self.logger.debug('Unable to fetch node: %s', ex)

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
                        session,
                        node,
                        spot_instance_request,
                        max_register_duration,
                    )
                except Exception: # pylint: disable=broad-except
                    self.logger.exception(
                        'Error processing spot instance request [%s]',
                        spot_instance_request,
                    )
            finally:
                session.close()
                queue.task_done()
        self.logger.debug('Exiting worker')

    async def process_spot_instance_request(
            self,
            ec2_conn: EC2Connection,
            session: Session,
            instance: dict,
            spot_instance_request: dict,
            max_register_duration: float,
    ) -> None:
        """
        :raises EC2ResponseError:
        """

        sir_id = spot_instance_request.get('spot_instance_request_id')
        if sir_id is None:
            with await self.__bad_request_lock:
                self.__bad_requests.append(sir_id)

            return

        if instance and instance.state == 'Installed':
            self.logger.debug(
                'Installed node [%s] already associated with spot instance'
                ' request [%s]', instance.name, sir_id
            )
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

        create_time = dateutil.parser.isoparse(result[0].create_time)
        self.logger.debug(
            'sir: [%s], state: [%s], status code: [%s], created at: [%s]',
            sir_id,
            result[0].state,
            result[0].status.code,
            create_time,
        )

        jump_table = {
            'active': self.__handle_active_spot_requests,
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

        self.logger.debug(
            'Calling handler for state: [%s]',
            result[0].state
        )
        await handler(
            result[0].status.code,
            sir_id,
            ec2_conn,
            result[0].instance_id,
            instance,
            spot_instance_request,
            create_time,
            session,
            max_register_duration,
        )

    async def __handle_active_spot_requests(
            self, status_code, sir_id, ec2_conn, instance_id, instance,        # pylint: disable=unused-argument
            spot_instance_request, create_time, session, max_register_duration # pylint: disable=unused-argument
    ):
        if status_code != 'fulfilled':
            return

        self.logger.debug(
            'Waiting for node for spot instance'
            ' request [%s]', sir_id
        )

        await self.__fulfilled_request_handler(
            ec2_conn,
            session,
            instance_id,
            spot_instance_request,
            create_time,
            max_register_duration,
        )

    async def __handle_open_spot_requests(
            self, status_code, sir_id, ec2_conn,          # pylint: disable=unused-argument
            instance_id, instance, spot_instance_request, # pylint: disable=unused-argument
            create_time, session, max_register_duration   # pylint: disable=unused-argument
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

    async def __handle_closed_spot_requests(
            self, status_code, sir_id, ec2_conn, # pylint: disable=unused-argument
            instance_id, instance,               # pylint: disable=unused-argument
            spot_instance_request, create_time,  # pylint: disable=unused-argument
            session, max_register_duration       # pylint: disable=unused-argument
    ):
        if status_code == 'marked-for-termination':
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

        # Instance is terminated.  We can remove the request.
        self.logger.info(
            'Deleting spot instance request id [%s] for terminated instance', sir_id
        )
        self.metadata_ws_api.deleteMetadata(
            filter_key=sir_id,
        )

    async def __handle_cancelled_spot_requests(
            self, status_code, sir_id, ec2_conn,
            instance_id, instance,
            spot_instance_request, create_time, session, max_register_duration
    ):
        if status_code == 'canceled-before-fulfillment':
            # Never had a instance so we must remove the request.
            self.logger.info(
                'Deleting spot instance request id [%s]', sir_id,
            )

            self.metadata_ws_api.deleteMetadata(
                filter_key=sir_id,
            )
            return

        if status_code == 'request-canceled-and-instance-running':
            if instance is None:
                # Need to check if launch has instance registered.
                await self.__fulfilled_request_handler(
                    ec2_conn,
                    session,
                    instance_id,
                    spot_instance_request,
                    create_time,
                    max_register_duration,
                )

        if status_code in (
                'instance-terminated-by-user',
                'instance-terminated-capacity-oversubscribed',
        ):
            self.logger.info(
                'Deleting spot instance request id [%s] for terminated instance [%s]',
                sir_id, instance_id
            )
            self.metadata_ws_api.deleteMetadata(
                filter_key=sir_id,
            )

    async def __handle_failed_spot_requests(
            self, status_code, sir_id, ec2_conn,           # pylint: disable=unused-argument
            instance_id, instance, spot_instance_request,  # pylint: disable=unused-argument
            create_time, session, max_register_duration):  # pylint: disable=unused-argument
        # This request is dead in the water; nothing more can happen
        return

    async def __fulfilled_request_handler(
            self,
            ec2_conn: EC2Connection,
            session: Session,
            instance_id: str,
            spot_instance_request: dict,
            create_time: datetime.datetime,
            max_register_duration: float,
    ):
        """Called when processing valid spot instance request"""

        sir_id = spot_instance_request.get('spot_instance_request_id')
        node = self.__get_node_by_instance(session, instance_id)
        if not node or node.state != 'Installed':
            waiting_seconds = time.time() - create_time.timestamp()

            if waiting_seconds > max_register_duration:
                self.logger.warn(
                    'Terminating instance [%s] as it failed to register in [%d] second(s)',
                    instance_id, max_register_duration)
                ec2_conn.terminate_instances(instance_ids=[instance_id])
            else:
                self.logger.info(
                    'Unable to find instance in database: [%s], instance will be terminated '
                    'in [%d] second(s) if it fails to register.',
                    instance_id, max_register_duration - waiting_seconds
                )

            return None

        result = self.__get_spot_instance_metadata(session, sir_id)
        if not result:
            self.logger.error(
                'Unable to find matching spot instance request: %s',
                sir_id,
            )

            return None

        self.logger.info(
            'Matching spot instance request [%s] to instance id [%s]',
            sir_id, instance_id
        )

        node.instance.instance_metadata.append(result)
        session.commit()

    def __get_spot_instance_metadata(self, session: Session,
                                     sir_id: str) -> Optional[InstanceMetadata]:
        try:
            return session.query(
                InstanceMetadata
            ).filter(InstanceMetadata.key == sir_id).one()  # noqa
        except NoResultFound:
            pass

        return None

    def __get_node_by_instance(self, session: Session,
                               instance_id: str) -> Optional[Node]:
        try:
            return session.query(InstanceMapping).filter(
                InstanceMapping.instance == instance_id  # noqa
            ).one().node
        except NoResultFound:
            pass

        return None


def main():
    """
    Entry point when running as a daemon or from the command line.
    """
    parser = argparse.ArgumentParser()
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

    parser.add_argument(
        '--max-register-duration', '-d', type=int,
        default=SPOT_INSTANCE_REGISTER_MAX_WAIT,
        metavar='SECONDS',
        help='Maximum amount of time to wait for spot instance to register (in seconds)',
    )

    polling_group = parser.add_argument_group('Polling Options')

    polling_group.add_argument(
        '--polling-interval', '-p', type=int,
        default=get_polling_interval(),
        metavar='SECONDS',
        help='Polling interval (in seconds)',
    )

    polling_group.add_argument('--one-time', action='store_true',
                               dest='one_time', default=False,
                               help='Run one loop and exit')

    parser.add_argument_group(polling_group)

    args = parser.parse_args()

    # Ensure logger is instantiated _after_ process is daemonized
    logger = logging.getLogger(__name__)

    logger.setLevel(logging.DEBUG)

    if args.debug or args.foreground:
        output_handler = logging.StreamHandler()
    else:
        # create console handler and set level to debug
        output_handler = logging.handlers.TimedRotatingFileHandler(
            '/var/log/tortuga_awsspotd', when='midnight')

    if args.debug:
        output_handler.setLevel(logging.DEBUG)
    else:
        output_handler.setLevel(logging.INFO)

    # create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # add formatter to ch
    output_handler.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(output_handler)

    klass = AWSSpotdAppClass(polling_interval=args.polling_interval,
                             max_register_duration=args.max_register_duration, logger=logger,
                             one_time=args.one_time)

    foreground = True if args.debug else args.foreground

    daemon = Daemonize(
        app='awsspotd',
        pid=args.pidfile,
        action=klass.run,
        verbose=args.verbose,
        foreground=foreground,
    )

    daemon.start()


def get_polling_interval(logger=None):
    """
    Return the periodic polling interval referencing a configuraiton
    file and the then defaulting to a reasonable value if not present.
    """
    interval = SPOT_INSTANCE_POLLING_INTERVAL
    config_manager = ConfigManager()
    base_dir = config_manager.getKitConfigBase()
    try:
        config_parser = configparser.ConfigParser()
        config_parser.read(os.path.join(base_dir, CONFIG_FILE))
        interval = int(config_parser.get(CONFIG_SECTION, CONFIG_INTERVAL_SECS))
    except Exception as ex: # pylint: disable=broad-except
        if logger:
            logger.error(
                'Unable to load configuration file [%s].  Using defaults.', ex)
    return interval


if __name__ == '__main__':
    main()
else:
    # importing here prevents the celery task loading step when running as a daemon
    from tortuga.tasks.celery import app
    from celery.schedules import schedule

    @app.on_after_finalize.connect
    def setup_periodic_tasks(sender, **kwargs): # pylint: disable=unused-argument
        """
        Register with celery to run the spot_checker periodically.
        """
        logger = logging.getLogger(__name__)
        interval = get_polling_interval(logger)
        logger.info(
            'Setting-up periodic task to run every %s minutes: spot_checker', interval)
        sender.add_periodic_task(
            schedule(run_every=interval),
            spot_checker.s(),
        )

    @app.task()
    def spot_checker():
        """
        Make sure spot instances follow the proper lifecycle.
        """
        logger = logging.getLogger(__name__)
        spot_app: AWSSpotdAppClass = AWSSpotdAppClass(
            logger=logger,
            one_time=True,
        )
        spot_app.run()

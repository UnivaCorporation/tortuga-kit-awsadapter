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

import boto
import mock

from moto import mock_ec2_deprecated

from tortuga.db.models.node import Node
from tortuga.resourceAdapter.aws.aws import Aws, ResourceAdapter
from tortuga.db.hardwareProfilesDbHandler import HardwareProfilesDbHandler
from tortuga.db.softwareProfilesDbHandler import SoftwareProfilesDbHandler


def test_instantiation():
    """
    Simple test to ensure resource adapter can be instantiated
    """

    assert Aws()


def test_instantiation_with_addHostSession():
    """
    Simple test to ensure resource adapter can be instantiated
    """

    adapter = Aws(addHostSession=123)

    assert adapter.addHostSession == 123


def test_installer_public_ipaddress():
    with mock.patch(
            'tortuga.resourceAdapter.aws.Aws.installer_public_ipaddress',
            new_callable=mock.PropertyMock) \
            as installer_public_ipaddress_mock:
        installer_public_ipaddress_mock.return_value = '1.2.3.4'

        assert Aws()._get_installer_ip() == '1.2.3.4'


def test_installer_public_ipaddress_with_hardwareprofile():
    class DummyNic:
        def __init__(self, ip):
            self.ip = ip

    class DummyHardwareProfile:
        def __init__(self):
            self.nics = [
                DummyNic('1.2.3.4'),
                DummyNic('2.3.4.5'),
            ]

    ip = Aws()._get_installer_ip(hardwareprofile=DummyHardwareProfile())

    assert ip == '1.2.3.4'


@mock.patch.object(Aws, '_load_config_from_database')
def test_deleteNode(load_config_dict_mock, dbm):
    load_config_dict_mock.return_value = {
        'awsAccessKey': 'the_key',
        'awsSecretKey': 'the_secret'
    }

    with mock_ec2_deprecated():
        with dbm.session() as session:
            adapter = Aws()

            node = session.query(Node).filter(
                Node.name == 'ip-10-10-10-1.ec2.internal').one()

            adapter.deleteNode([node])


@mock.patch.object(Aws, 'fire_provisioned_event')
@mock.patch.object(Aws, '_pre_add_host')
@mock.patch.object(Aws, '_load_config_from_database')
@mock_ec2_deprecated
def test_start(load_config_dict_mock, pre_add_host_mock,
               fire_provisioned_even_mock, dbm):
    """
    Test ResourceAdapter.start() workflow
    """

    load_config_dict_mock.return_value = {
        'awsAccessKey': 'the_key',
        'awsSecretKey': 'the_secret',
        'keypair': 'the_keypair',
        'ami': 'ami-abcd1234',
        'use_instance_hostname': 'true',
        'instancetype': 'the_instancetype'
    }

    with dbm.session() as session:
        adapter = Aws(addHostSession='123EXAMPLE')

        # override default sleep time
        adapter.LAUNCH_INITIAL_SLEEP_TIME = 0.0

        adapter.TEST_MODE = True

        addNodesRequest = {
            'count': 2,
        }

        hardwareprofile = HardwareProfilesDbHandler().getHardwareProfile(
            session, 'aws2'
        )

        softwareprofile = SoftwareProfilesDbHandler().getSoftwareProfile(
            session, 'compute'
        )

        nodes = adapter.start(
            addNodesRequest, session, hardwareprofile,
            dbSoftwareProfile=softwareprofile
        )

        assert nodes and isinstance(nodes, list) and \
            isinstance(nodes[0], Node)

        assert nodes[0].instance.instance

        if len(nodes) > 1:
            assert nodes[1].instance.instance

    pre_add_host_mock.assert_called()

    fire_provisioned_even_mock.assert_called()


@mock.patch.object(Aws, 'fire_provisioned_event')
@mock.patch.object(Aws, '_pre_add_host')
@mock.patch.object(Aws, '_load_config_from_database')
@mock_ec2_deprecated
def test_start_update_node(load_config_dict_mock, pre_add_host_mock,
                           fire_provisioned_event_mock, dbm):
    configDict = {
        'awsAccessKey': 'the_key',
        'awsSecretKey': 'the_secret',
        'ami': 'ami-abcd1234',
        'use_instance_hostname': 'true',
    }

    load_config_dict_mock.return_value = configDict

    with dbm.session() as session:
        addHostSession = '123EXAMPLE'

        adapter = Aws(addHostSession=addHostSession)

        # override default sleep time
        adapter.LAUNCH_INITIAL_SLEEP_TIME = 0.0

        count = 3

        hardwareprofile = HardwareProfilesDbHandler().getHardwareProfile(
            session, 'aws2'
        )

        softwareprofile = SoftwareProfilesDbHandler().getSoftwareProfile(
            session, 'compute'
        )

        # create instances to be associated with nodes
        conn = boto.connect_ec2(configDict['awsAccessKey'],
                                configDict['awsSecretKey'])

        conn.run_instances(
            configDict['ami'],
            min_count=count,
            max_count=count
        )

        # get newly created instances
        instances = conn.get_only_instances()

        # intialize 'addNodesRequest'
        addNodesRequest = {
            'nodeDetails': [],
        }

        for instance in instances:
            addNodesRequest['nodeDetails'].append({
                'name': instance.private_dns_name,
                'metadata': {
                    'ec2_instance_id': instance.id,
                    'ec2_ipaddress': instance.private_ip_address,
                }
            })

        # call Aws.start() with instance metadata
        nodes = adapter.start(
            addNodesRequest, session, hardwareprofile,
            dbSoftwareProfile=softwareprofile
        )

        assert nodes and len(nodes) == count

        assert isinstance(nodes[0], Node)

        assert nodes[0].softwareprofile.name == softwareprofile.name

        assert nodes[0].hardwareprofile.name == hardwareprofile.name

        assert nodes[0].addHostSession == addHostSession

        fire_provisioned_event_mock.assert_called()

        pre_add_host_mock.assert_called()

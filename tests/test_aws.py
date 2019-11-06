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

import mock
import pytest

import boto
from moto import mock_ec2, mock_ec2_deprecated
from tortuga.db.hardwareProfilesDbHandler import HardwareProfilesDbHandler
from tortuga.db.models.node import Node
from tortuga.db.softwareProfilesDbHandler import SoftwareProfilesDbHandler
from tortuga.resourceAdapter.aws.aws import Aws, ResourceAdapter


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
        'awsaccesskey': 'the_key',
        'awssecretkey': 'the_secret'
    }

    with mock_ec2_deprecated():
        with dbm.session() as session:
            adapter = Aws()

            node = session.query(Node).filter(
                Node.name == 'ip-10-10-10-1.ec2.internal').one()

            adapter.deleteNode([node])


@mock.patch.object(Aws, 'get_instance_size_mapping')
@mock.patch.object(Aws, 'fire_provisioned_event')
@mock.patch.object(Aws, '_pre_add_host')
@mock.patch.object(Aws, '_load_config_from_database')
@mock_ec2
def test_start(load_config_dict_mock, pre_add_host_mock,
               fire_provisioned_even_mock, get_instance_size_mapping_mock,
               dbm, valid_ami):
    """
    Test ResourceAdapter.start() workflow
    """

    get_instance_size_mapping_mock.return_value = 8

    load_config_dict_mock.return_value = {
        'awsaccesskey': 'the_key',
        'awssecretkey': 'the_secret',
        'keypair': 'the_keypair',
        'ami': valid_ami,
        'use_instance_hostname': 'true',
        'instancetype': 'the_instancetype'
    }

    with dbm.session() as session:
        adapter = Aws(addHostSession='123EXAMPLE')

        # override default sleep time
        adapter.LAUNCH_INITIAL_SLEEP_TIME = 0.0

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
                           fire_provisioned_event_mock, dbm, valid_ami):
    configDict = {
        'awsaccesskey': 'the_key',
        'awssecretkey': 'the_secret',
        'ami': valid_ami,
        'use_instance_hostname': 'true',
        'instancetype': 'm5.large',
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
        conn = boto.connect_ec2(configDict['awsaccesskey'],
                                configDict['awssecretkey'])

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


@pytest.mark.parametrize(
    "proxy_host,proxy_port,proxy_user,proxy_pass",
    [
        (None, None, None, None),
        ('proxy.com', 1234, None, None),
        ('proxy.com', 1234, 'test.user', 'p4ssw0rd'),
    ]
)
def test_boto3_conn_setup(proxy_host, proxy_port, proxy_user, proxy_pass):
    """Test setup of boto3 connection"""

    # Construct configDict
    configDict = {
        'awsaccesskey': 'the_key',
        'awssecretkey': 'the_secret',
        'region': 'us-east-1',
    }
    if proxy_host:
        configDict['proxy_host'] = proxy_host
        configDict['proxy_port'] = proxy_port
        if proxy_user:
            configDict['proxy_user'] = proxy_user
            configDict['proxy_pass'] = proxy_pass

    # Set up adapter and process configDict
    adapter = Aws()
    adapter.process_config(configDict)

    # Get boto3 connection
    session_cls = 'tortuga.resourceAdapter.aws.aws.boto3.Session'
    config_cls = 'tortuga.resourceAdapter.aws.aws.Config'
    with mock.patch(session_cls) as boto3_session_mock, \
         mock.patch(config_cls) as botocore_config_mock:
        conn3 = adapter.getEC2Connection3(configDict)

    # Test session call args/kwargs
    session_call_kwargs = boto3_session_mock.call_args[1]
    assert len(session_call_kwargs) == 3
    assert session_call_kwargs['aws_access_key_id'] == \
        configDict['awsaccesskey']
    assert session_call_kwargs['aws_secret_access_key'] == \
        configDict['awssecretkey']
    assert session_call_kwargs['region_name'] == configDict['region']

    # Test config call args/kwargs if proxy used
    if proxy_host is not None:
        config_call_kwargs = botocore_config_mock.call_args[1]
        proxy_dict = config_call_kwargs['proxies']
        assert len(proxy_dict) == 1
        assert 'http' in proxy_dict
        proxy_url = f'{proxy_host}:{proxy_port}'
        if proxy_user is not None:
            proxy_url = f'{proxy_user}:{proxy_pass}@{proxy_url}'
        assert proxy_dict['http'] == proxy_url


def test_boto3_validate_launch_args():
    """Test validation of launch args for boto3 connection"""
    configDict = {
        'awsaccesskey': 'the_key',
        'awssecretkey': 'the_secret',
        'region': 'us-east-1',
        'placementgroup': 'testgroup',
    }

    # Set up adapter and process configDict
    adapter = Aws()
    adapter.process_config(configDict)

    # Get boto3 connection
    conn3 = adapter.getEC2Connection3(configDict)

    # We have to mock this directly since moto doesn't implement
    # a mock of create_placement_group at present (Oct. 2019)
    with mock.patch.object(conn3, 'create_placement_group') as mock_cpg:
        adapter._validate_ec2_launch_args(conn3, configDict)

    # Check results
    call_kwargs = mock_cpg.call_args[1]
    assert len(call_kwargs) == 2
    assert call_kwargs['GroupName'] == configDict['placementgroup']
    assert call_kwargs['Strategy'] == 'cluster'


@pytest.mark.parametrize(
    "use_instance_hostname,name_tag,use_node,use_addNodesRequest",
    [
        (False, None, True, False),
        (True, None, True, False),
        (False, 'instance_name', True, False),
        (True, 'instance_name', True, False),
        (False, None, False, True),
        (True, None, False, True),
        (False, 'instance_name', False, True),
        (True, 'instance_name', False, True),
    ]
)
def test_get_instance_specific_tags(use_instance_hostname, name_tag, use_node,
                                    use_addNodesRequest):
    """Test tags generated for instance"""
    # Set up configDict
    configDict = {
        'region': 'us-east-1',
        'installer_ip': '127.0.0.1',
        'tags': {'key1': 'value1', 'key2': 'value2'},
        'use_instance_hostname': use_instance_hostname,
    }
    if name_tag:
        configDict['tags']['Name'] = name_tag

    # Set up node mock, if needed
    node = None
    if use_node:
        node = mock.Mock(spec=Node)
        node.name = 'node_name'
        node.hardwareprofile.name = 'node_hwp'
        node.softwareprofile.name = 'node_swp'

    # Set up addNodesRequest, if needed
    addNodesRequest = {}
    if use_addNodesRequest:
        addNodesRequest = {'softwareProfile': 'swp', 'hardwareProfile': 'hwp'}

    # Set up adapter - no need to process configDict since the tags
    # are already in processed form
    adapter = Aws()

    # Get boto3 connection
    conn3 = adapter.getEC2Connection3(configDict)

    # Get tags
    tags = adapter._Aws__get_instance_specific_tags(
        configDict, node=node, addNodesRequest=addNodesRequest
    )

    # Manually generate expected contents
    expected_hwp_name = node.hardwareprofile.name if use_node \
        else addNodesRequest['hardwareProfile']
    expected_swp_name = node.softwareprofile.name if use_node \
        else addNodesRequest['softwareProfile']
    expected_name = configDict.get('tags').get('Name', None)
    if use_instance_hostname:
        if expected_name is None:
            expected_name = 'Tortuga compute node'
    elif node:
        expected_name = node.name
    expected_num_tags = 4 + int(expected_name is not None) + \
        (len(configDict['tags']) - int(bool(name_tag)))

    # Check results
    assert len(tags) == expected_num_tags
    assert tags['tortuga:installer_ipaddress'] == configDict['installer_ip']
    assert tags['tortuga:installer_hostname'] == \
        adapter.installer_public_hostname
    assert tags['tortuga:softwareprofile'] == expected_swp_name
    assert tags['tortuga:hardwareprofile'] == expected_hwp_name
    for k,v in configDict['tags'].items():
        # 'Name' tag will not *always* match - we check it below
        if k != 'Name':
            assert tags[k] == v
    if expected_name is None:
        assert 'Name' not in tags
    else:
        assert tags['Name'] == expected_name


@pytest.mark.parametrize("subnet_id", ['fake_subnet_id', None])
def test_get_common_launch_args3(subnet_id, valid_ami):
    """Test construction of launch args dict for run_instances with boto3"""
    # Set up configDict
    configDict = {
        'keypair': 'keypair_name',
        'instancetype': 't2.large',
        'region': 'us-east-1',
        'zone': 'fake_zone',
        'installer_ip': '127.0.0.1',
        'use_instance_hostname': False,
        'placementgroup': 'fake_placementgroup',
        'cloud_init': None,
        'ami': valid_ami,
        'aki': 'fake_kernel_id',
        'ari': 'fake_ramdisk_id',
        'ebs_optimized': True,
        'monitoring_enabled': False,
        'iam_instance_profile_name': 'fake_profile_name',
        'subnet_id': subnet_id,
        'securitygroup': ['sg-1234'],
        'associate_public_ip_address': True,
        'use_tags': True,
        'tags': {'key1': 'value1', 'key2': 'value2'},
    }

    # Set up adapter and process configDict
    adapter = Aws()
    #adapter.process_config(configDict)

    # Get boto3 connection
    conn3 = adapter.getEC2Connection3(configDict)

    # Set up a mock node
    node = mock.Mock(spec=Node)
    node.hardwareprofile.name = 'hwp_name'
    node.softwareprofile.name = 'swp_name'
    node.name = 'node_name'

    # Execute function
    with mock_ec2():
        run_args = adapter._Aws__get_common_launch_args3(conn3, configDict,
                                                         node=node)

    # Check results
    assert run_args['EbsOptimized'] == configDict['ebs_optimized']
    assert run_args['IamInstanceProfile']['Name'] == \
        configDict['iam_instance_profile_name']
    assert run_args['InstanceType'] == configDict['instancetype']
    assert run_args['KernelId'] == configDict['aki']
    assert run_args['KeyName'] == configDict['keypair']
    assert run_args['Monitoring']['Enabled'] == \
        configDict['monitoring_enabled']
    assert run_args['Placement']['AvailabilityZone'] == configDict['zone']
    assert run_args['Placement']['GroupName'] == configDict['placementgroup']
    assert run_args['RamdiskId'] == configDict['ari']

    # Depends on subnet id
    if subnet_id is not None:
        assert 'NetworkInterfaces' in run_args
        assert len(run_args['NetworkInterfaces']) == 1
        ni = run_args['NetworkInterfaces'][0]
        assert ni['AssociatePublicIpAddress'] == \
            configDict['associate_public_ip_address']
        assert ni['Groups'] == configDict['securitygroup']
        assert ni['SubnetId'] == configDict['subnet_id']
    else:
        assert 'SecurityGroupIds' in run_args
        assert run_args['SecurityGroupIds'] == configDict['securitygroup']

    # Don't need to check instance tags here, since it's done in another test
    tag_specs = \
        {d['ResourceType']: d['Tags'] for d in run_args['TagSpecifications']}
    volume_tag_specs = {d['Key']: d['Value'] for d in tag_specs['volume']}
    assert len(volume_tag_specs) == len(configDict['tags'])
    for k in volume_tag_specs:
        assert volume_tag_specs[k] == configDict['tags'][k]


def test_launch_EC2(valid_ami):
    """Test full EC2 launch process"""
    # Set up configDict
    configDict = {
        'keypair': 'keypair_name',
        'instancetype': 't2.large',
        'region': 'us-east-1',
        'awsaccesskey': 'the_key',
        'awssecretkey': 'the_secret',
        'zone': 'fake_zone',
        'use_instance_hostname': False,
        'block_device_map': '/dev/sda1=:30:true:io1:500:encrypted',
        'ami': valid_ami,
        'aki': 'fake_kernel_id',
        'ari': 'fake_ramdisk_id',
        'ebs_optimized': True,
        'monitoring_enabled': False,
        'iam_instance_profile_name': 'fake_profile_name',
        'subnet_id': None,
        'securitygroup': ['sg-1234'],
        'associate_public_ip_address': True,
        'tags': 'key1=value1 key2=value2',
    }

    # Set up adapter and process configDict
    adapter = Aws()
    adapter.process_config(configDict)

    # Set up a mock node
    node = mock.Mock(spec=Node)
    node.hardwareprofile.name = 'hwp_name'
    node.softwareprofile.name = 'swp_name'
    node.name = 'node_name'

    # Run __launchEC2
    with mock_ec2():
        # Get boto3 connection
        conn3 = adapter.getEC2Connection3(configDict)

        # Create mock vpc and subnet
        vpc = conn3.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = conn3.create_subnet(CidrBlock='10.0.0.0/18', VpcId=vpc.id)
        configDict['subnet_id'] = subnet.id

        # Launch instances
        result = adapter._Aws__launchEC2(conn3, configDict, count=1, node=node)

    # Check results
    assert len(result) == 1
    instance = result[0]
    assert instance.image.id == configDict['ami']
    assert instance.key_pair.key_name == configDict['keypair']
    assert instance.instance_type == configDict['instancetype']
    assert instance.vpc_id == vpc.id
    assert instance.subnet_id == subnet.id
    assert len(instance.network_interfaces) == 1
    assert instance.network_interfaces[0].groups[0]['GroupName'] == \
        configDict['securitygroup'][0]
    # NOTE: moto does not give the correct result for these two. I have tested
    # manually on AWS and confirmed that they work as expected.
    #assert instance.ebs_optimized == configDict['ebs_optimized']
    #assert instance.monitoring['state'] == 'disabled'

    # Check tags
    instance_tags = {d['Key']: d['Value'] for d in instance.tags}
    assert instance_tags['Name'] == node.name
    assert instance_tags['key1'] == 'value1'
    assert instance_tags['key2'] == 'value2'
    assert instance_tags['tortuga:softwareprofile'] == \
        node.softwareprofile.name
    assert instance_tags['tortuga:hardwareprofile'] == \
        node.hardwareprofile.name
    assert instance_tags['tortuga:installer_ipaddress'] == \
        adapter.installer_public_ipaddress
    assert instance_tags['tortuga:installer_hostname'] == \
        adapter.installer_public_hostname

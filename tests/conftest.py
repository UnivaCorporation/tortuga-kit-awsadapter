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

import pytest
from passlib.hash import pbkdf2_sha256
from sqlalchemy import create_engine

import boto.ec2
import tortuga.resourceAdapter
import tortuga.resourceAdapter.aws.aws
from moto import mock_ec2_deprecated
from tortuga.config.configManager import ConfigManager, getfqdn
from tortuga.db.dbManager import DbManager
from tortuga.db.models.admin import Admin
from tortuga.db.models.component import Component
from tortuga.db.models.hardwareProfile import HardwareProfile
from tortuga.db.models.hardwareProfileNetwork import HardwareProfileNetwork
from tortuga.db.models.instanceMapping import InstanceMapping
from tortuga.db.models.kit import Kit
from tortuga.db.models.network import Network
from tortuga.db.models.networkDevice import NetworkDevice
from tortuga.db.models.nic import Nic
from tortuga.db.models.node import Node
from tortuga.db.models.operatingSystem import OperatingSystem
from tortuga.db.models.operatingSystemFamily import OperatingSystemFamily
from tortuga.db.models.resourceAdapter import ResourceAdapter
from tortuga.db.models.resourceAdapterConfig import ResourceAdapterConfig
from tortuga.db.models.resourceAdapterSetting import ResourceAdapterSetting
from tortuga.db.models.softwareProfile import SoftwareProfile
from tortuga.db.models.tag import Tag
from tortuga.deployer.dbUtility import init_global_parameters, primeDb
from tortuga.objects import osFamilyInfo, osInfo
from tortuga.resourceAdapter.aws import Aws


#
# Override some settings so that validation doesn't complain
#
Aws.settings['awsAccessKey'].required = False
Aws.settings['awsSecretKey'].required = False
Aws.settings['keypair'].required = False
Aws.settings['instancetype'].required = False
Aws.settings['cloud_init_script_template'].must_exist = False
Aws.settings['user_data_script_template'].must_exist = False


@pytest.fixture()
@mock_ec2_deprecated
def valid_ami():
    """
    Return valid Moto AMI ID
    """

    with mock_ec2_deprecated():
        ec2_conn = boto.ec2.connect_to_region('us-east-1')

        amis = ec2_conn.get_all_images()

        return amis[0].id


@pytest.fixture(autouse=True)
def disable_DbManager(monkeypatch, dbm):
    monkeypatch.setattr(tortuga.db.dbManager, 'DbManager', lambda: dbm)


@pytest.fixture(scope='session')
def cm():
    return ConfigManager()


@pytest.fixture(scope='class')
def cm_class(request, cm):
    request.cls.cm = cm


@pytest.fixture(scope='session')
@mock_ec2_deprecated
def dbm():
    dbmgr = DbManager(create_engine('sqlite:///:memory:', echo=False))

    dbmgr.init_database()

    rhel7_os_family_info = osFamilyInfo.OsFamilyInfo('rhel', '7', 'x86_64')

    os_info = osInfo.OsInfo('centos', '7.4', 'x86_64')
    os_info.setOsFamilyInfo(rhel7_os_family_info)

    installer_fqdn = getfqdn()

    settings = {
        'language': 'en',
        'keyboard': 'en_US',
        'timezone': 'UTC',
        'utc': 'true',
        'intWebPort': '8008',
        'intWebServicePort': '8444',
        'adminPort': '8443',
        'eulaAccepted': 'true',
        'depotpath': '/opt/tortuga/depot',
        'osInfo': os_info,
        'fqdn': installer_fqdn,
        'installer_software_profile': 'Installer',
        'installer_hardware_profile': 'Installer',
    }

    with dbmgr.session() as session:
        primeDb(session, settings)

        init_global_parameters(session, settings)

        # create sample tags
        all_tags = []

        for idx in range(1, 5 + 1):
            tag = Tag(name='tag{:d}'.format(idx),
                      value='value{:d}'.format(idx))

            all_tags.append(tag)

        installer_node = session.query(Node).filter(
            Node.name == installer_fqdn).one()

        os_ = session.query(OperatingSystem).filter(
            OperatingSystem.name == 'centos').one()

        rhel7_os_family = session.query(OperatingSystemFamily).filter(
            OperatingSystemFamily.name == 'rhel').one()

        # add add'l operating system/family
        rhel75_os = OperatingSystem(name='rhel', version='7.5', arch='x86_64')
        rhel75_os.family = rhel7_os_family

        session.add(rhel75_os)

        admin = Admin(username='admin',
                      password=pbkdf2_sha256.hash('password'),
                      realname='realname',
                      description='description')

        session.add(admin)

        eth1_network_device = NetworkDevice(name='eth1')

        # Add dummy provisioning network
        network = Network()
        network.address = '10.2.0.0'
        network.netmask = '255.255.255.0'
        network.name = 'Provisioning network on eth1'
        network.type = 'provision'

        session.add(network)

        # create 'hardwareprofilenetwork' entry
        hwpn1 = HardwareProfileNetwork(
            hardwareprofile=installer_node.hardwareprofile,
            network=network,
            networkdevice=eth1_network_device
        )

        # create nic on installer
        installer_nic = Nic()
        installer_nic.ip = '10.2.0.1'
        installer_nic.network = network
        installer_nic.networkdevice = eth1_network_device

        installer_node.nics = [installer_nic]

        # create 'base' kit
        kit = Kit()
        kit.name = 'base'
        kit.version = '6.3.1'
        kit.iteration = '0'
        kit.description = 'Sample base kit'

        installer_component = Component(name='installer', version='6.3')
        installer_component.family = [rhel7_os_family]
        installer_component.kit = kit

        core_component = Component(name='core',
                                   version='6.3',
                                   description='Compute component')
        core_component.family = [rhel7_os_family]
        core_component.kit = kit

        session.add(kit)

        # create OS kit
        os_kit = Kit(name='centos', version='7.4', iteration='0')
        os_kit.isOs = True
        os_component = Component(name='centos-7.4-x86_64', version='7.4')
        os_component.os = [os_]
        os_component.kit = os_kit
        os_kit.components.append(os_component)

        session.add(os_kit)

        # create resource adapter kit
        ra_kit = Kit(name='awsadapter', version='0.0.1', iteration='0')
        ra_component = Component(name='management', version='0.0.1')
        ra_component.family.append(rhel7_os_family)
        ra_kit.components.append(ra_component)

        installer_node.softwareprofile.components.append(ra_component)
        installer_node.softwareprofile.components.append(installer_component)
        session.commit()

        # create 'default' resource adapter
        default_adapter = ResourceAdapter(name='default')
        default_adapter.kit = kit

        # create resource adapter
        aws_adapter = ResourceAdapter(name='AWS')
        aws_adapter.kit = ra_kit

        aws_adapter_cfg = ResourceAdapterConfig(
            name='default',
            description='Example default resource adapter configuration'
        )

        with mock_ec2_deprecated():
            ec2_conn = boto.ec2.connect_to_region('us-east-1')

            amis = ec2_conn.get_all_images()

            aws_adapter_cfg.configuration.append(
                ResourceAdapterSetting(key='ami', value=amis[0].id)
            )

        aws_adapter.resource_adapter_config.append(aws_adapter_cfg)

        # add second resource adapter configuration
        aws_adapter_cfg2 = ResourceAdapterConfig(
            name='nondefault', admin=admin)
        aws_adapter_cfg2.configuration.append(
            ResourceAdapterSetting(key='another_key', value='another_value')
        )

        session.add(aws_adapter)

        # create 'AWS' hardware profile
        aws_hwprofile = HardwareProfile(name='AWS')
        aws_hwprofile.location = 'remote'
        aws_hwprofile.resourceadapter = aws_adapter

        session.add(aws_hwprofile)

        aws_hwprofile2 = HardwareProfile(
            name='aws2',
            location='remote',
            resourceadapter=aws_adapter,
            nameFormat='*'
        )

        session.add(aws_hwprofile2)

        # create 'compute' software profile
        compute_swprofile = SoftwareProfile(name='compute')
        compute_swprofile.os = os_
        compute_swprofile.components = [core_component]
        compute_swprofile.type = 'compute'

        # create 'compute2' software profile
        compute2_swprofile = SoftwareProfile(name='compute2',
                                             os=os_,
                                             components=[core_component],
                                             type='compute')

        # map 'AWS' to 'compute'
        aws_hwprofile.mappedsoftwareprofiles.append(compute_swprofile)
        aws_hwprofile2.mappedsoftwareprofiles.append(compute_swprofile)

        # create 'localiron' hardware profile
        localiron_hwprofile = HardwareProfile(
            name='localiron', nameFormat='compute-#NN')
        localiron_hwprofile.resourceadapter = default_adapter
        localiron_hwprofile.mappedsoftwareprofiles.append(compute_swprofile)
        localiron_hwprofile.mappedsoftwareprofiles.append(compute2_swprofile)

        localiron_hwprofile.hardwareprofilenetworks.append(hwpn1)

        # create 'nonetwork' hardware profile
        nonetwork_hwprofile = HardwareProfile(name='nonetwork')
        nonetwork_hwprofile.resourceadapter = default_adapter
        nonetwork_hwprofile.mappedsoftwareprofiles.append(compute_swprofile)

        eth0_networkdevice = NetworkDevice(name='eth0')

        # create compute (compute-01, compute-02, ...) nodes
        for n in range(1, 11):
            compute_node = Node(
                name='compute-{0:02d}.private'.format(n),
                state='Installed'
            )
            compute_node.addHostSession = '1234'
            compute_node.softwareprofile = compute_swprofile
            compute_node.hardwareprofile = localiron_hwprofile

            compute_node.nics.append(
                Nic(
                    ip='10.2.0.{}'.format(100 + n),
                    mac='FF:00:00:00:00:00:{:02x}'.format(100 + n),
                    boot=True,
                    network=network,
                    networkdevice=eth0_networkdevice
                )
            )

            if n in (1, 2):
                # compute-01 and compute-02 have all tags
                compute_node.tags.extend(all_tags)
            elif n in (3, 4):
                # compute-03 and compute-04 have 'tag1' and 'tag2'
                compute_node.tags.append(all_tags[0])
                compute_node.tags.append(all_tags[1])
            elif n in (5, 6):
                # compute-05 and compute-06 have 'tag2' and 'tag3'
                compute_node.tags.append(all_tags[1])
                compute_node.tags.append(all_tags[2])
            elif n == 7:
                # compute-07 has 'tag4'
                compute_node.tags.append(all_tags[3])
            elif n == 8:
                # compute-08 has 'tag5'
                compute_node.tags.append(all_tags[4])

            session.add(compute_node)

        # create arbitrary aws nodes
        for idx in range(1, 10):
            new_node = Node(
                name='ip-10-10-10-{:0d}.ec2.internal'.format(idx),
                hardwareprofile=aws_hwprofile,
                softwareprofile=compute_swprofile,
                isIdle=False
            )

            new_node.instance = InstanceMapping(
                instance='i-{:08x}'.format(idx)
            )

            new_node.instance.resource_adapter_configuration = aws_adapter_cfg

            session.add(new_node)

        # create arbitrary hardware profiles
        hwprofile1 = HardwareProfile(name='profile1', tags=[all_tags[0]])
        hwprofile2 = HardwareProfile(name='profile2', tags=[all_tags[1]])

        session.add(hwprofile1)
        session.add(hwprofile2)

        # create arbitrary software profiles
        SoftwareProfile(name='swprofile1',
                        os=os_,
                        type='compute',
                        tags=[all_tags[0]])

        SoftwareProfile(name='swprofile2',
                        os=os_,
                        type='compute',
                        tags=[all_tags[1]])

        session.commit()

    return dbmgr


@pytest.fixture(scope='class')
def dbm_class(request, dbm):
    request.cls.dbm = dbm

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
from mock import patch

from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.resourceAdapter.aws import Aws
from tortuga.resourceAdapter.resourceAdapter import ResourceAdapter


@pytest.fixture
def minimal_configDict():
    return {
        'ami': 'ami-XXXXXXXX',
    }


def test_invalid_adapter_configuration(dbm):
    """Ensure exception is raissed from missing required settings"""

    with dbm.session() as session:
        with pytest.raises(ConfigurationError):
            with patch.object(
                    ResourceAdapter, '_load_config_from_database', return_value={}):
                adapter = Aws()
                adapter.session = session

                adapter.get_config()


def test_minimal_config(dbm, minimal_configDict):
    with dbm.session() as session:
        with patch.object(
                ResourceAdapter, '_load_config_from_database',
                return_value=minimal_configDict):
            adapter = Aws()
            adapter.session = session

            config = adapter.get_config()

            assert 'ami' in config

            assert config['ami'] == 'ami-XXXXXXXX'

            assert isinstance(config['override_dns_domain'], bool)

            assert not config['override_dns_domain']


def test_override_dns_domain_enabled(dbm):
    configDict = {
        'ami': 'ami-XXXXXXXX',
        'override_dns_domain': 'true',
    }

    with dbm.session() as session:
        with patch.object(
                ResourceAdapter, '_load_config_from_database',
                return_value=configDict):
            adapter = Aws()
            adapter.session = session

            config = adapter.get_config()

            assert isinstance(config['override_dns_domain'], bool)

            assert config['override_dns_domain']

            # when 'dns_domain' is not specified in the resource adapter
            # configuration, the current private DNS zone is used. We don't
            # care what the value is as long as there is one.
            assert isinstance(config['dns_domain'], str)
            assert config['dns_domain']


def test_override_dns_domain_enabled_with_dns_domain(dbm):
    configDict = {
        'ami': 'ami-XXXXXXXX',
        'override_dns_domain': 'true',
        'dns_domain': 'mydomain',
    }

    with dbm.session() as session:
        with patch.object(
                ResourceAdapter, '_load_config_from_database',
                return_value=configDict):
            adapter = Aws()
            adapter.session = session

            config = adapter.get_config()

            assert isinstance(config['override_dns_domain'], bool)

            assert config['override_dns_domain']

            assert config['dns_domain'] == 'mydomain'


@mock.patch.object(Aws, '_load_config_from_database')
def test_missing_ami_setting(load_config_dict_mock, dbm):
    load_config_dict_mock.return_value = {}

    with dbm.session() as session:
        with pytest.raises(ConfigurationError):
            adapter = Aws()
            adapter.session = session

            adapter.get_config()


@mock.patch.object(Aws, '_load_config_from_database')
def test_use_instance_hostname(load_config_dict_mock, dbm):
    load_config_dict_mock.return_value = {
        'ami': 'ami-XXXXXX',
        'override_dns_domain': 'true',
        'dns_domain': 'cloud.example.com',
        'use_instance_hostname': 'false',
    }

    with dbm.session() as session:
        adapter = Aws()
        adapter.session = session

        result = adapter.get_config()

        assert result['dns_domain'] == 'cloud.example.com'


@mock.patch.object(Aws, '_load_config_from_database')
def test_defaults(load_config_dict_mock, dbm):
    load_config_dict_mock.return_value = {
        'ami': 'ami-XXXXXXXX',
    }

    with dbm.session() as session:
        adapter = Aws()
        adapter.session = session

        result = adapter.get_config()

        assert result['ami'] == 'ami-XXXXXXXX'

        assert result['use_instance_hostname']

        assert result['associate_public_ip_address']

        assert not result['cloud_init']

        assert not result.get('override_dns_domain', None)

        assert not result.get('use_domain_from_dhcp_option_set', None)

        assert result['region'] == 'us-east-1'


@mock.patch.object(Aws, '_load_config_from_database')
def test_invalid_settings(load_config_dict_mock, dbm):
    load_config_dict_mock.return_value = {
        'ami': 'ami-XXXXXXXX',
        'unrecognized': 'setting',
        'another_bad_setting': 'value',
    }

    with dbm.session() as session:
        with pytest.raises(ConfigurationError):
            adapter = Aws()
            adapter.session = session

            adapter.get_config()

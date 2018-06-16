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

    with pytest.raises(ConfigurationError):
        with patch.object(
                ResourceAdapter, '_loadConfigDict', return_value={}):
            Aws().getResourceAdapterConfig()


def test_minimal_config(minimal_configDict):
    with patch.object(
            ResourceAdapter, '_loadConfigDict',
            return_value=minimal_configDict):
        config = Aws().getResourceAdapterConfig()

        assert 'ami' in config

        assert config['ami'] == 'ami-XXXXXXXX'

        assert isinstance(config['override_dns_domain'], bool)

        assert not config['override_dns_domain']

        assert config['dns_domain'] is None


def test_override_dns_domain_enabled():
    configDict = {
        'ami': 'ami-XXXXXXXX',
        'override_dns_domain': 'true',
    }

    with patch.object(
            ResourceAdapter, '_loadConfigDict',
            return_value=configDict):
        config = Aws().getResourceAdapterConfig()

        assert isinstance(config['override_dns_domain'], bool)

        assert config['override_dns_domain']

        # when 'dns_domain' is not specified in the resource adapter
        # configuration, the current private DNS zone is used. We don't
        # care what the value is as long as there is one.
        assert isinstance(config['dns_domain'], str)
        assert config['dns_domain']


def test_override_dns_domain_enabled_with_dns_domain():
    configDict = {
        'ami': 'ami-XXXXXXXX',
        'override_dns_domain': 'true',
        'dns_domain': 'mydomain',
    }

    with patch.object(
            ResourceAdapter, '_loadConfigDict',
            return_value=configDict):
        config = Aws().getResourceAdapterConfig()

        assert isinstance(config['override_dns_domain'], bool)

        assert config['override_dns_domain']

        assert config['dns_domain'] == 'mydomain'


@mock.patch.object(Aws, '_loadConfigDict')
def test_missing_ami_setting(load_config_dict_mock):
    load_config_dict_mock.return_value = {}

    with pytest.raises(ConfigurationError):
        Aws().getResourceAdapterConfig()


@mock.patch.object(Aws, '_loadConfigDict')
def test_use_instance_hostname(load_config_dict_mock):
    load_config_dict_mock.return_value = {
        'ami': 'ami-XXXXXX',
        'override_dns_domain': 'true',
        'dns_domain': 'cloud.example.com',
        'use_instance_hostname': 'false',
    }

    adapter = Aws()

    result = adapter.getResourceAdapterConfig()

    assert result['dns_domain'] == 'cloud.example.com'


@mock.patch.object(Aws, '_loadConfigDict')
def test_defaults(load_config_dict_mock):
    load_config_dict_mock.return_value = {
        'ami': 'ami-XXXXXXXX',
    }

    adapter = Aws()

    result = adapter.getResourceAdapterConfig()

    assert result['ami'] == 'ami-XXXXXXXX'

    assert result['use_instance_hostname']

    assert result['use_tags']

    assert result['associate_public_ip_address']

    assert not result['cloud_init']

    assert not result['override_dns_domain']

    assert not result['use_domain_from_dhcp_option_set']

    assert result['region'] == 'us-east-1'


@mock.patch.object(Aws, '_loadConfigDict')
def test_invalid_settings(load_config_dict_mock):
    load_config_dict_mock.return_value = {
        'ami': 'ami-XXXXXXXX',
        'unrecognized': 'setting',
        'another_bad_setting': 'value',
    }

    with pytest.raises(ConfigurationError):
        Aws().getResourceAdapterConfig()

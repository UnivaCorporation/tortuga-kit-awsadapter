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

from mock import patch
import pytest
from tortuga.resourceAdapter.resourceAdapter import ResourceAdapter
from tortuga.resourceAdapter.aws import Aws
from tortuga.exceptions.configurationError import ConfigurationError


@pytest.fixture
def minimal_configDict():
    return {
        'ami': 'ami-XXXXXXXX',
    }


def test_invalid_adapter_configuration():
    """Ensure exception is raissed from missing required settings"""

    with pytest.raises(ConfigurationError):
        with patch.object(
                ResourceAdapter, 'getResourceAdapterConfig', return_value={}):
            Aws().getResourceAdapterConfig()


def test_minimal_config(minimal_configDict):
    with patch.object(
            ResourceAdapter, 'getResourceAdapterConfig',
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
        'override_dns_domain': str(True),
    }

    with patch.object(
            ResourceAdapter, 'getResourceAdapterConfig',
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
        'override_dns_domain': str(True),
        'dns_domain': 'mydomain',
    }

    with patch.object(
            ResourceAdapter, 'getResourceAdapterConfig',
            return_value=configDict):
        config = Aws().getResourceAdapterConfig()

        assert isinstance(config['override_dns_domain'], bool)

        assert config['override_dns_domain']

        assert config['dns_domain'] == 'mydomain'

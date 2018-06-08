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
import mock
from tortuga.resourceAdapter.aws import Aws
from tortuga.exceptions.configurationError import ConfigurationError


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

   assert not result['use_instance_hostname']

   assert result['use_tags']

   assert result['associate_public_ip_address']

   assert not result['cloud_init']

   assert not result['override_dns_domain']

   assert not result['use_domain_from_dhcp_option_set']

   assert result['region'] == 'us-east-1'

   print(result)


@mock.patch.object(Aws, '_loadConfigDict')
def test_invalid_settings(load_config_dict_mock):
   load_config_dict_mock.return_value = {
       'ami': 'ami-XXXXXXXX',
       'unrecognized': 'setting',
       'another_bad_setting': 'value',
   }

   with pytest.raises(ConfigurationError):
       Aws().getResourceAdapterConfig()

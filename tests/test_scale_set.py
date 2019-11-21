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

from boto.ec2.autoscale.tag import Tag as AutoscaleTag
from moto import mock_ec2
from tortuga.resourceAdapter.aws.aws import Aws

@pytest.mark.parametrize("name_tag", [None, 'scaleset_node'])
def test_scale_set_tags(name_tag):
    """Test scale set tag generation"""
    configDict = {
        'installer_ip': '123.456.7.89',
        'use_instance_hostname': True,
        'tags': {'other tag': 'value'}
    }
    if name_tag:
        configDict['tags']['Name'] = name_tag
    group_name = 'fake_group'
    hardware_profile = 'hwp'
    software_profile = 'swp'
    adapter = Aws()
    adapter.process_config(configDict)

    # Get tags
    tags = adapter._get_scale_set_tags(group_name, configDict,
                                       hardware_profile, software_profile)

    # Check basic tag properties
    assert len(tags) == 6
    for tag in tags:
        assert tag.resource_id == group_name
        assert tag.resource_type == 'auto-scaling-group'
        assert tag.propagate_at_launch

    # Convert to dict for more specific testing
    tag_dict = {tag.key: tag for tag in tags}
    assert tag_dict['tortuga-hardwareprofile'].value == hardware_profile
    assert tag_dict['tortuga-softwareprofile'].value == software_profile
    assert tag_dict['tortuga-installer_hostname'].value == \
        adapter._sanitze_tag_value(adapter.installer_public_hostname)
    assert tag_dict['tortuga-installer_ipaddress'].value == \
        adapter._sanitze_tag_value(configDict['installer_ip'])
    assert tag_dict['other tag'].value == configDict['tags']['other tag']

    # Check name
    expected_name = name_tag if name_tag else 'Tortuga compute node'
    assert tag_dict['Name'].value == expected_name

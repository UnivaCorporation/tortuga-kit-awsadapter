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

import shlex
from typing import Dict, Optional


def ec2_get_root_block_devices(block_devices):
    # Helper function for determining the root block device for an AMI
    return [device for device in block_devices
            if device in ('/dev/xvda', '/dev/sda', '/dev/sda1')]


def _quote_str(value: Optional[str]) -> str:
    """Helper function used for generating instance metadata"""
    if value is None:
        return 'None'

    return '\'%s\'' % value


def _get_encoded_list(items):
    """Return Python list encoded in a string"""
    return '[' + ', '.join(
        [_quote_str(item) for item in items]
    ) + ']' if items else '[]'


def parse_cfg_tags(value: str) -> Dict[str, str]:
    tags = {}

    for tagdef in shlex.split(value):
        key, value = tagdef.rsplit('=', 1) \
            if '=' in tagdef else (tagdef, '')
        tags[key] = value

    return tags

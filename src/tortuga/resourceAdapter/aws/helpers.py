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
import redis
import shlex
from typing import Dict
from subprocess import check_output


def ec2_get_root_block_devices(ami):
    # Helper function for determining the root block device for an AMI
    return [device for device in ami.block_device_mapping.keys()
            if device in ('/dev/xvda', '/dev/sda', '/dev/sda1')]


def _get_encoded_list(items):
    """Return Python list encoded in a string"""
    return '[' + ', '.join(['\'%s\'' % (item) for item in items]) + ']' \
        if items else '[]'


def parse_cfg_tags(value: str) -> Dict[str, str]:
    tags = {}

    for tagdef in shlex.split(value):
        key, value = tagdef.rsplit('=', 1) \
            if '=' in tagdef else (tagdef, '')
        tags[key] = value

    return tags


FACTER_PATH = '/opt/puppetlabs/bin/facter'


def get_redis_client():
    try:
        uri = check_output(
            [FACTER_PATH, 'redis_url']
        ).strip().decode()
    except:
        uri = None

    if not uri:
        uri = 'localhost:6379'

    host, port = uri.split(':')

    return redis.StrictRedis(
        host=host,
        port=int(port),
        db=0
    )
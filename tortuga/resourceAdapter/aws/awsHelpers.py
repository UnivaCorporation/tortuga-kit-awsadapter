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

import boto.ec2
from tortuga.exceptions.configurationError import ConfigurationError


def get_ec2_region(aws_access_key_id, aws_secret_access_key, region=None):
    regions = boto.ec2.regions(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key)

    if not region:
        # Use first region in list ('us-east-1')
        result = [region for region in regions
                  if region.name == 'us-east-1']

        if not result:
            raise ConfigurationError(
                'Unable to find default region [{}]'.format(
                    'us-east-1'))

        return result[0]

    for tmpregion in regions:
        if str(tmpregion.name) == region:
            return tmpregion

    raise ConfigurationError('Unknown AWS region: {0}'.format(region))

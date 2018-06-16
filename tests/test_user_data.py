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

import io

import pytest
from mock import patch

from tortuga.resourceAdapter.aws import Aws
from tortuga.resourceAdapter.resourceAdapter import ResourceAdapter

from jinja2 import Template


minimal_user_data_config = {
    'ami': 'ami-XYXYXYXYX',
    'cloud_init': 'true',
    'user_data_script_template': 'blah.txt'
}


minimal_user_data_config_with_node = {
    'ami': 'ami-XYXYXYXYX',
    'cloud_init': 'true',
    'user_data_script_template': 'blah.txt',
    'use_instance_hostname': 'false',
}


minimal_cloud_init_config = {
    'ami': 'ami=FFFFFFFF',
    'cloud_init_script_template': 'notblah.txt',
}


@patch.object(Aws, '_get_config_file_path', return_value='xxxxxxxx')
@patch.object(Aws, '_loadConfigDict',
              return_value=minimal_user_data_config)
def test_get_user_data(
        load_config_dict_mock, get_config_path_mock): \
        # pylint: disable=unused-argument
    """
    Use mock data to expand SETTINGS macro
    """

    file_contents = '''
#!/usr/bin/env python

### SETTINGS


def main():
    pass


if __name__ == '__main__':
    main()
'''

    fp = io.StringIO(file_contents)

    adapter = Aws()

    config = adapter.getResourceAdapterConfig()

    result = adapter._Aws__get_user_data_script(fp, config)

    assert result and isinstance(result, str)

    assert get_config_path_mock.called_with('blah.txt')


@patch.object(Aws, '_get_config_file_path', return_value='xxxxxxxx')
@patch.object(Aws, '_loadConfigDict',
              return_value=minimal_user_data_config_with_node)
def test_get_user_data_with_node(
        load_config_dict_mock, get_config_path_mock): \
        # pylint: disable=unused-argument
    """
    Use mock data to expand SETTINGS macro
    """

    file_contents = '''
#!/usr/bin/env python

### SETTINGS


def main():
    pass


if __name__ == '__main__':
    main()
'''

    fp = io.StringIO(file_contents)

    adapter = Aws()

    config = adapter.getResourceAdapterConfig()

    class DummyNode:
        def __init__(self, name):
            self.name = name

    node = DummyNode('mynode.example.com')

    result = adapter._Aws__get_user_data_script(fp, config, node=node)

    assert result and isinstance(result, str)

    assert get_config_path_mock.called_with('blah.txt')


@patch.object(Aws, '_get_config_file_path', return_value='xxxxxxxx')
@patch.object(Aws, '_loadConfigDict',
              return_value=minimal_cloud_init_config)
def test_expand_cloud_init_user_data_template(
        load_config_dict_mock, get_config_path_mock): \
        # pylint: disable=unused-argument
    """
    Load sample data as Jinja2 template
    """

    tmpl = '''
#!/usr/bin/env python

installer = '{{ installer }}'


def main():
    pass


if __name__ == '__main__':
    main()
'''

    adapter = Aws()

    config = adapter.getResourceAdapterConfig()

    result = adapter.expand_cloud_init_user_data_template(
        config, template=Template(tmpl))

    assert result and isinstance(result, str)

    assert get_config_path_mock.called_with('notblah.txt')

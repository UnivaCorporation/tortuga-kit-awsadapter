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

from tortuga.kit.installer import KitInstallerBase
from tortuga.kit.mixins import ResourceAdapterMixin


class AWSKitInstaller(ResourceAdapterMixin, KitInstallerBase):
    config_files = [
        'bootstrap.tmpl',
        'bootstrap-aws-centos7.py',
        'bootstrap-aws-centos8.py',
        'bootstrap-aws-ubuntu18.py',
        'aws-instances.csv',
        'aws-bootstrap-offline.tmpl',
        'cloud-config-secondary-disk.yaml',
    ]
    puppet_modules = ['univa-tortuga_kit_awsadapter']
    resource_adapter_name = 'AWS'

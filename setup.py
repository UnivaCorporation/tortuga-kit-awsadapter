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

import os
import subprocess

from setuptools import find_packages, setup


version = '7.0.0'


def get_git_revision():
    cmd = 'git rev-parse --short HEAD'

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    result, _ = p.communicate()
    p.wait()

    return result.decode().rstrip()


git_revision = get_git_revision()

module_version = f'{version}+rev{git_revision}'

if os.getenv('CI_PIPELINE_ID'):
    module_version += '.{}'.format(os.getenv('CI_PIPELINE_ID'))


setup(
    name='tortuga-aws-adapter',
    version=module_version,
    url='http://univa.com',
    author='Univa Corporation',
    author_email='support@univa.com',
    license='Apache 2.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    namespace_packages=[
        'tortuga',
        'tortuga.resourceAdapter'
    ],
    zip_safe=False,
    install_requires=[
        'boto',
        'boto3',
        'gevent<1.3.2',
        'awscli',
        'click',
        'colorama',
        'daemonize',
        'Jinja2',
    ],
    entry_points={
        'console_scripts': [
            'awsspotd=tortuga.scripts.awsspotd:main',
            'cancel-spot-instance-requests=tortuga.scripts.cancel_spot_instance_requests:main',
            'get-current-spot-instance-price=tortuga.scripts.get_current_spot_instance_price:main',
            'list-spot-instance-nodes=tortuga.scripts.list_spot_instance_nodes:main',
            'list-spot-instance-requests=tortuga.scripts.list_spot_instance_requests:main',
            'request-spot-instances=tortuga.scripts.request_spot_instances:main',
            'setup-aws=tortuga.scripts.setup_aws:main'
        ]
    }
)

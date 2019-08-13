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

from setuptools import find_packages, setup


VERSION = '7.0.3'


def get_requirements():
    with open('requirements.txt') as fp:
        requirements = [buf.rstrip() for buf in fp.readlines()]

    return requirements


setup(
    name='tortuga-aws-adapter',
    version=VERSION,
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
    install_requires=get_requirements(),
    entry_points={
        'console_scripts': [
            'cancel-spot-instance-requests=tortuga.scripts.cancel_spot_instance_requests:main',
            'get-current-spot-instance-price=tortuga.scripts.get_current_spot_instance_price:main',
            'list-spot-instance-requests=tortuga.scripts.list_spot_instance_requests:main',
            'request-spot-instances=tortuga.scripts.request_spot_instances:main',
            'setup-aws=tortuga.scripts.setup_aws:main'
        ]
    }
)

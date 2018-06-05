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


setup(
    name='tortuga-aws-adapter',
    version='6.3.0',
    url='http://univa.com',
    author='Univa Corp',
    author_email='info@univa.com',
    license='Commercial',
    packages=find_packages(exclude=['tortuga_kits']),
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
    ],
    entry_points={
        'console_scripts': [
            'awsspotd=tortuga.scripts.awsspotd:main',
            'cancel-spot-instance-requests=tortuga.scripts.cancel_spot_instance_requests:main',
            'get-current-spot-instance-price=tortuga.scripts.get_current_spot_instance_price:main',
            'list-spot-instance-nodes=tortuga.scripts.list_spot_instance_nodes:main',
            'list-spot-instance-requests=tortuga.scripts.list_spot_instance_requests:main',
            'request-spot-instances=tortuga.scripts.request_spot_instances:main',
            'setup-aws=tortuga.scripts.setup_aws:main',
        ]
    }
)

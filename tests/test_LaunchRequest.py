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

from tortuga.resourceAdapter.aws import launchRequest


def test_init_LaunchRequest():
    hardwareprofile = {'testkey1': 'testvalue1'}
    softwareprofile = {'testkey2': 'testvalue2'}

    lr = launchRequest.LaunchRequest(hardwareprofile=hardwareprofile,
                                     softwareprofile=softwareprofile)


    assert lr.hardwareprofile['testkey1'] == 'testvalue1'


def test_init_node_request_queue():
    nodes = ['node{:02d}' for node in range(6)]

    rq = launchRequest.init_node_request_queue(nodes)

    assert isinstance(rq, list) and len(rq) == 6

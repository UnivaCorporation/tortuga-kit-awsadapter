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


class LaunchRequest(object):
    def __init__(self, hardwareprofile=None, softwareprofile=None):
        self.hardwareprofile = hardwareprofile
        self.softwareprofile = softwareprofile
        self.node_request_queue = []
        self.addNodesRequest = None
        self.configDict = None
        self.conn = None


def init_node_request_queue(nodes):
    """
    Construct a lookup table of nodes
    """

    node_request_queue = []

    for node in nodes:
        node_request = {
            'node': node,
            'status': 'pending',
        }

        node_request_queue.append(node_request)

    return node_request_queue

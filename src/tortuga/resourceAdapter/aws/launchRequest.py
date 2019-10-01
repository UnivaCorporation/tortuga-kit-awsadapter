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


from typing import Any, Dict, List, Optional

from tortuga.db.models.hardwareProfile import HardwareProfile
from tortuga.db.models.node import Node
from tortuga.db.models.softwareProfile import SoftwareProfile
from boto.ec2.connection import EC2Connection
from boto3.resources.base import ServiceResource


class LaunchRequest(object):
    def __init__(self, hardwareprofile: Optional[HardwareProfile] = None,
                 softwareprofile: Optional[SoftwareProfile] = None) -> None:
        self.hardwareprofile = hardwareprofile
        self.softwareprofile = softwareprofile
        self.node_request_queue: List[Dict[str, Any]] = []
        self.addNodesRequest: Optional[dict] = None
        self.configDict: Optional[Dict[str, Any]] = None
        self.conn: Optional[EC2Connection] = None
        self.conn3: Optional[ServiceResource] = None


def init_node_request_queue(nodes: List[Node]) -> List[Dict[str, Any]]:
    """
    Construct a lookup table of nodes
    """

    node_request_queue: List[Dict[str, Any]] = []

    for node in nodes:
        node_request = {
            'node': node,
            'status': 'pending',
        }

        node_request_queue.append(node_request)

    return node_request_queue

#!/usr/bin/env python

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

import configparser

from tortuga.db.dbManager import DbManager
from tortuga.db.nodesDbHandler import NodesDbHandler


def main():
    spot_instance_cache = configparser.ConfigParser()
    spot_instance_cache.read('/opt/tortuga/var/spot-instances.conf')

    spot_instances = []
    for item in spot_instance_cache.sections():
        try:
            spot_instances.append(spot_instance_cache.get(item, 'node'))
        except configparser.NoOptionError:
            pass

    with DbManager().session() as session:
        for node in NodesDbHandler().getNodeList(session):
            if node.hardwareprofile.resourceadapter and \
                    node.hardwareprofile.resourceadapter.name == 'AWS':
                if node.name in spot_instances:
                    print(node.name)

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

from .commonSpotInstanceCli import CommonSpotInstanceCLI
from .spot_common import SpotInstanceCommonMixin


class ListSpotInstanceNodesCLI(CommonSpotInstanceCLI, SpotInstanceCommonMixin):
    def runCommand(self):
        self.parseArgs()

        for sir_id, sir_metadata, name in self._iter_spot_instance_requests():
            if name is None:
                continue

            print(name)


def main():
    ListSpotInstanceNodesCLI().run()

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

import json
from typing import Generator, List, Optional, Tuple

from tortuga.wsapi.resourceAdapterConfigurationWsApi import \
    ResourceAdapterConfigurationWsApi


class SpotInstanceCommonMixin:
    def _get_spot_instance_request(
                self,
                sir_id: str,
            ) -> Optional[Tuple[str, dict, Optional[str]]]:
        result = self.metadataWsApi.list(filter_key=sir_id)
        if not result:
            return None

        return self.__get_spot_instance_tuple(result[0])

    def _iter_spot_instance_requests(
            self,
            adapter_cfg_name: Optional[str] = None
            ) -> Generator[Tuple[str, dict, Optional[str]], None, None]:
        """
        Iterate on instance metadata results; filtering out any non-spot
        instance requests as well as those not matching the specified
        resource adapter configuration profile.
        """
        for item in self.metadataWsApi.list():
            if not item['key'].startswith('sir-'):
                continue

            sir_id, sir_metadata, node_name = self.__get_spot_instance_tuple(item)

            if adapter_cfg_name and \
                    sir_metadata['resource_adapter_configuration'] != \
                    adapter_cfg_name:
                continue

            yield sir_id, sir_metadata, node_name

    def __get_spot_instance_tuple(self, item: dict) \
            -> Tuple[str, dict, Optional[str]]:

        sir_metadata = json.loads(item['value'])

        name = item['instance']['node']['name'] \
            if item.get('instance') else None

        return item['key'], sir_metadata, name

    def _get_adapter_cfg(self, name: str) -> dict:
        """
        Return list of resource adapter configuration dicts
        """
        resourceAdapterConfigurationWsApi = self.configureClient(ResourceAdapterConfigurationWsApi)

        adapter_cfg = resourceAdapterConfigurationWsApi.get(
            'AWS',
            'Default',
        )['configuration']

        result = self.__get_adapter_cfg_as_dict(adapter_cfg)

        if name != 'Default':
            resource_adapter_cfg = resourceAdapterConfigurationWsApi.get(
                'AWS',
                name,
            )['configuration']

            result.update(self.__get_adapter_cfg_as_dict(resource_adapter_cfg))

        return result

    def __get_adapter_cfg_as_dict(self, adapter_cfg: List[dict]):
        return {item['key']: item for item in adapter_cfg}

    def _get_adapter_cfg_key(self, adapter_cfg: dict, key: str) \
            -> Optional[str]:
        """
        Iterate over list of resource adapter configuration key-value pairs
        """
        entry = adapter_cfg.get(key)
        if entry is None:
            return entry

        return entry.get('value')

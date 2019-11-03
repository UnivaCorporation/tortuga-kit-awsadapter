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
import logging
from typing import Optional

from tortuga.events.listeners.base import BaseListener
from tortuga.events.types import (ResourceRequestCreated,
                                  ResourceRequestUpdated,
                                  ResourceRequestDeleted)
from tortuga.resources.types import (get_resource_request_class,
                                     BaseResourceRequest,
                                     ScaleSetResourceRequest)
from tortuga.resources.store import ResourceRequestStore
from tortuga.resources.manager import ResourceRequestStoreManager

from tortuga.resourceAdapter.resourceAdapterFactory import get_api
from tortuga.resourceAdapter.resourceAdapter import ResourceAdapter

from sqlalchemy.orm import sessionmaker
from tortuga.web_service.database import dbm

logger = logging.getLogger(__name__)


class AwsScaleSetListenerMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._store: ResourceRequestStore = ResourceRequestStoreManager.get()
        Session = sessionmaker(bind=dbm.engine)
        self.session = Session()

    def get_resource_adapter(self) -> ResourceAdapter:
        adapter = get_api('AWS')
        adapter.session = self.session
        return adapter

    def is_valid_request(self, resource_request: BaseResourceRequest) -> bool:
        #
        # Only ScaleSetResourceRequests are valid for these listeners
        #
        if not isinstance(resource_request, ScaleSetResourceRequest):
            return False
        #
        # Only requests destined for AWS are valid for these listeners
        #
        if resource_request.resourceadapter_name != 'AWS':
            return False
        #
        # If we get this far, then the request is valid
        #
        return True

    def get_scale_set_request(self,
                              event) -> Optional[ScaleSetResourceRequest]:
        #
        # Get the resource request
        #
        rr = self._store.get(event.resourcerequest_id)
        #
        # Validate the resource request
        #
        if not self.is_valid_request(rr):
            return None

        return rr

    def get_previous_scale_set_request(
            self, event) -> Optional[ScaleSetResourceRequest]:
        #
        # Make sure the event has the previous resource request attribute
        #
        if not hasattr(event, 'previous_resourcerequest'):
            return None
        #
        # Deserialize the previous resource request
        #
        rr_data = event.previous_resourcerequest
        resource_request_class = get_resource_request_class(
            rr_data['resource_type'])
        schema_class = resource_request_class.get_schema_class()
        unmarshalled = schema_class().load(event.previous_resourcerequest)
        rr = resource_request_class(**unmarshalled.data)
        #
        # Validate the resource request
        #
        if not self.is_valid_request(rr):
            return None

        return rr


class AwsScaleSetCreatedListener(AwsScaleSetListenerMixin, BaseListener):
    name = 'aws-scale-set-created-listener'
    event_types = [ResourceRequestCreated]

    def run(self, event: ResourceRequestCreated):
        #
        # If no scale set for AWS, then ignore this event
        #
        ssr = self.get_scale_set_request(event)
        if ssr is None:
            return

        logger.warning('Scale set create request for AWS: %s', ssr.id)

        # Load the resource adapter for this request
        try:
            adapter = self.get_resource_adapter()
        except Exception as ex:
            logger.warning('Resource adapter is not installed: %s', ex)
            self._store.delete(ssr.id)
            return
 
        try:
            # Now create the scale set
            adapter.create_scale_set(name=ssr.id,
                minCount=ssr.min_nodes, maxCount=ssr.max_nodes,
                desiredCount=ssr.desired_nodes,
                resourceAdapterProfile=ssr.resourceadapter_profile_name,
                hardwareProfile=ssr.hardwareprofile_name,
                softwareProfile=ssr.softwareprofile_name,
                adapter_args=ssr.adapter_arguments)
        except Exception as ex:
            logger.error("Error creating resource request: %s", ex)
            self._store.delete(ssr.id)
        


class AwsScaleSetUpdatedListener(AwsScaleSetListenerMixin, BaseListener):
    name = 'aws-scale-set-updated-listener'
    event_types = [ResourceRequestUpdated]

    def run(self, event: ResourceRequestUpdated):
        #
        # If no scale set for AWS, then ignore this event
        #
        ssr = self.get_scale_set_request(event)
        if ssr is None:
            return

        logger.warning('Scale set update request for AWS: %s', ssr.id)

        # Load the resource adapter for this request
        try:
            adapter = self.get_resource_adapter()
        except Exception as ex:
            logger.warning('Resource adapter is not installed: %s', ex)
            return

        try:
            # Now create the scale set
            adapter.update_scale_set(name=ssr.id,
                minCount=ssr.min_nodes, maxCount=ssr.max_nodes,
                desiredCount=ssr.desired_nodes,
                resourceAdapterProfile=ssr.resourceadapter_profile_name,
                hardwareProfile=ssr.hardwareprofile_name,
                softwareProfile=ssr.softwareprofile_name,
                adapter_args=ssr.adapter_arguments)
        except Exception as ex:
            logger.error("Error updating resource request: %s", ex)
            old = self.get_previous_scale_set_request(event)
            self._store.save(old)




class AwsScaleSetDeletedListener(AwsScaleSetListenerMixin, BaseListener):
    name = 'aws-scale-set-deleted-listener'
    event_types = [ResourceRequestDeleted]

    def run(self, event: ResourceRequestDeleted):
        #
        # If no scale set for AWS, then ignore this event
        #
        ssr = self.get_previous_scale_set_request(event)
        if ssr is None:
            return

        logger.warning('Scale set delete request for AWS: %s', ssr.id)

        # Load the resource adapter for this request
        try:
            adapter = self.get_resource_adapter()
        except Exception as ex:
            logger.warning('Resource adapter is not installed: %s', ex)
            return

        # Now create the scale set
        try:
            adapter.delete_scale_set(name=ssr.id,
                resourceAdapterProfile=ssr.resourceadapter_profile_name)
        except Exception as ex:
            logger.error("Error deleting resource request: %s", ex)
            self._store.save(ssr)


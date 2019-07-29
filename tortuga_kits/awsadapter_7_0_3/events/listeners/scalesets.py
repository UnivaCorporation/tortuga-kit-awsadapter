#############################################################################
#
# This code is the Property, a Trade Secret and the Confidential Information
# of Univa Corporation.
#
# Copyright 2008-2018 Univa Corporation. All Rights Reserved. Access is Restricted.
#
# It is provided to you under the terms of the
# Univa Term Software License Agreement.
#
# If you have any questions, please contact our Support Department.
#
# http://www.univa.com
#
#############################################################################
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


logger = logging.getLogger(__name__)


class AwsScaleSetListenerMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._store: ResourceRequestStore = ResourceRequestStoreManager.get()

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

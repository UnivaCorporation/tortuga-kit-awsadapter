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
import os
import json
import boto3
import argparse

from datetime import date
from tortuga.cli.base import Argument, Command
from typing import Any, Optional, Generator, Dict, Tuple


class LicenseUsageCommand(Command):
    """
    Grab the usage between 2 dates
    and write to CSV file.

    IAM permission 'ce:GetCostAndUsage'
    is required to gather the data.
    """
    name = 'usage'
    help = 'Create usage report'

    arguments = [
        Argument(
            '--start',
            help='YYYY-MM-DD',
            required=True
        ),
        Argument(
            '--end',
            help='YYYY-MM-DD',
            required=True
        ),
        Argument(
            '-o',
            '--output',
            help='Specify output file path',
            type=str,
            default=None
        )
    ]

    def __init__(self) -> None:
        """
        Initialise client and logger.

        :returns: None
        """
        super(LicenseUsageCommand, self).__init__()
        self._args = None
        self._client = boto3.client('ce')

    def execute(self, args: argparse.Namespace) -> None:
        """
        Iterate over each row and write to file.

        :returns: None
        """
        self._args = args

        start, end = self._string_to_date()

        if self._args.output:
            path: str = os.path.abspath(
                self._args.output
            )
        else:
            path: str = os.path.join(
                os.path.expanduser('~'),
                '{}_{}.json'.format(
                    self._args.start,
                    self._args.end
                )
            )

        with open(path, 'w') as f:
            for row in self._get_data(start, end):
                f.write(
                    json.dumps(row)
                )

    def _string_to_date(self) -> Tuple[date]:
        """
        Convert the arguments to date
        objects.

        :returns: Tuple Date Date
        """
        try:
            start: date = date.fromisoformat(self._args.start)
            end: date = date.fromisoformat(self._args.end)
        except AttributeError:  # Above method only in 3.7.
            split_start: Tuple[str] = self._args.start.split('-')
            split_end: Tuple[str] = self._args.end.split('-')

            split_start: Tuple[int] = map(int, split_start)
            split_end: Tuple[int] = map(int, split_end)

            start: date = date(*split_start)
            end: date = date(*split_end)

        return start, end

    def _get_data(self, start: date, end: date) -> Generator[Dict[Any, Any], None, None]:
        """
        Get the usage data from AWS.

        :param start: Date
        :param end: Date
        :returns: Generator Dictionary
        """
        page_token: Optional[str] = None

        while True:
            if page_token:
                kwargs: dict = {'NextPageToken': page_token}
            else:
                kwargs: dict = {}

            response: Dict[Any, Any] = self._client.get_cost_and_usage(
                TimePeriod={
                    'Start': start.strftime('%Y-%m-%d'),
                    'End':  end.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UsageQuantity'],
                GroupBy=[{
                    'Type': 'DIMENSION',
                    'Key': 'SERVICE',
                }, {
                    'Type': 'DIMENSION',
                    'Key': 'INSTANCE_TYPE'
                }],
                Filter={
                    'Dimensions': {
                        'Key': 'SERVICE',
                        'Values': [
                            'Amazon Elastic Compute Cloud - Compute'
                        ]
                    },
                    'Tags': {
                        'Key': 'tortuga',
                        'Values': ['installer_hostname']
                    }
                },
                **kwargs
            )

            for result in response['ResultsByTime']:
                yield result

            page_token = response.get('NextPageToken', None)
            if not page_token:
                break

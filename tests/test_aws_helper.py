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

import pytest

from tortuga.exceptions.nicNotFound import NicNotFound
from tortuga.resourceAdapter.aws.aws import get_primary_nic


class DummyNic:
    def __init__(self, **kwargs):
        self.boot = False

        for key, value in kwargs.items():
            setattr(self, key, value)


@pytest.mark.parametrize('nics,expected', [
    ((DummyNic(boot=True), DummyNic()), 0),
    ((DummyNic(), DummyNic(boot=True)), 1),
    ((DummyNic(), DummyNic(), DummyNic(boot=True)), 2),
    ((DummyNic(boot=True), DummyNic(), DummyNic()), 0),
    pytest.param((DummyNic(),), None,
                 marks=pytest.mark.xfail(raises=NicNotFound)),
    pytest.param((DummyNic(), DummyNic()), None,
                 marks=pytest.mark.xfail(raises=NicNotFound)),
])
def test_get_primary_nic(nics, expected):
    result = get_primary_nic(nics)

    assert result == nics[expected]

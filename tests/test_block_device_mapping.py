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

import pprint
import unittest

from tortuga.exceptions.invalidArgument import InvalidArgument
from tortuga.resourceAdapter.aws import Aws


class AwsAdapterTestSuite(unittest.TestCase):
    def setUp(self):
        self.adapter = Aws()

    def teardown(self):
        self.adapter = None

    def test_size_block_device_mapping(self):
        # One block device mapping entry
        sda_size = 60

        bdm = self.adapter._Aws__process_block_device_map(
            '/dev/sda=:%d' % (sda_size))

        self.assertTrue('/dev/sda' in bdm)

        self.assertEqual(int(bdm['/dev/sda'].size), sda_size)

    def test_ephemeral_block_device_mapping(self):
        ephemeral_name = 'ephemeral0'

        bdm = self.adapter._Aws__process_block_device_map(
            '/dev/sdb=%s' % (ephemeral_name))

        self.assertEqual(bdm['/dev/sdb'].ephemeral_name, ephemeral_name)

    def test_two_block_device_mapping(self):
        # Two block device mapping entries

        sda_size = 60
        ephemeral_name = 'ephemeral0'

        bdm = self.adapter._Aws__process_block_device_map(
            '/dev/sda=:%d,/dev/sdb=%s' % (sda_size, ephemeral_name))

        self.assertEqual(len(list(bdm.keys())), 2)

        self.assertTrue('/dev/sda' in bdm and '/dev/sdb' in bdm)

        self.assertEqual(int(bdm['/dev/sda'].size), sda_size)
        self.assertEqual(bdm['/dev/sdb'].ephemeral_name, ephemeral_name)

    def test_failed_block_device_mapping(self):
        self.assertRaises(
            InvalidArgument,
            self.adapter._Aws__process_block_device_map, 'chicken')

    def test_simple_snapshot_device_mapping(self):
        snapshot_id = 'snap-ABABABAB'

        bdm = self.adapter._Aws__process_block_device_map(
            '/dev/sda=%s' % (snapshot_id))

        # Match snapshot_name
        self.assertEqual(bdm['/dev/sda'].snapshot_id, snapshot_id)

    def test_io1_device_mapping(self):
        volume_type = 'io1'
        iops = 500

        bdm = self.adapter._Aws__process_block_device_map(
            '/dev/sda=:::%s:%d' % (volume_type, iops))

        # Match volume_type
        self.assertEqual(bdm['/dev/sda'].volume_type, volume_type)

        # Match iops
        self.assertEqual(int(bdm['/dev/sda'].iops), iops)

    def test_invalid_io1_device_mapping(self):
        volume_type = 'io1'

        self.assertRaises(
            InvalidArgument,
            self.adapter._Aws__process_block_device_map,
            '/dev/sda=:::%s' % (volume_type))

    def test_simple_encrypted_device_mapping(self):
        bdm = self.adapter._Aws__process_block_device_map(
            '/dev/sda=::::encrypted')

        self.assertTrue(bdm['/dev/sda'].encrypted)

    def test_snapshot_and_encrypted_device_mapping(self):
        snapshot_id = 'snap-BBBBBBBB'
        bdm = self.adapter._Aws__process_block_device_map(
            '/dev/sda=%s::::encrypted' % (snapshot_id))

        self.assertEqual(bdm['/dev/sda'].snapshot_id, snapshot_id)
        self.assertTrue(bdm['/dev/sda'].encrypted)

    def test_empty_device_mapping(self):
        bdm = self.adapter._Aws__process_block_device_map(
            '/dev/sda=::::')

        self.assertFalse(bdm['/dev/sda'].encrypted)


if __name__ == '__main__':
    unittest.main()

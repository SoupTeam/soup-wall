#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Descriptor handback parser controls; these do not qualify native execution."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('owner_self_loss',
    Path(__file__).parents[1] / 'ci' / 'observe-owner-self-loss.py')
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


class PacketTests(unittest.TestCase):
    def fixture(self):
        packet = {'format': 'sw-mcp/linux-crash-owner/1', 'instance': 'a' * 32,
                  'budget': {'budget_sha256': 'b' * 64, 'leaf': 'agentfw-mcp-' + 'c' * 32,
                             'device': 1, 'inode': 2, 'started_monotonic_nanos': 3}}
        return packet

    def parse(self, packet=None, *, header=None, ancillary=None, iovec=None, payload=None):
        packet = self.fixture() if packet is None else packet
        payload = json.dumps(packet).encode() if payload is None else payload
        memory = {100: header if header is not None else struct.pack('<QI4xQQQQI4x', 0, 0, 200, 1, 300, 48, 0),
                  200: iovec if iovec is not None else struct.pack('<QQ', 400, len(payload)),
                  300: ancillary if ancillary is not None else struct.pack('<Qii8i', 48, 1, 1, *range(3, 11)),
                  400: payload}
        def read(address, length):
            return memory[address][:length]
        return OBSERVER.descriptor_packet(read, 100, 'b' * 64)

    def test_exact_eight_descriptor_prepared_message(self):
        self.assertEqual(self.parse(), self.fixture()['budget'])

    def test_descriptor_counts_types_truncation_and_aliases_refuse(self):
        for args in (
            {'header': b''}, {'iovec': b''}, {'ancillary': b''},
            {'header': struct.pack('<QI4xQQQQI4x', 0, 0, 200, 2, 300, 48, 0)},
            {'header': struct.pack('<QI4xQQQQI4x', 0, 0, 200, 1, 300, 80, 0)},
            {'ancillary': struct.pack('<Qii8i', 48, 1, 2, *range(3, 11))},
            {'ancillary': struct.pack('<Qii8i', 48, 1, 1, *([3] * 8))},
            {'iovec': struct.pack('<QQ', 400, OBSERVER.MAX_PACKET + 1)},
        ):
            with self.subTest(args=args), self.assertRaises(OBSERVER.Incomplete):
                self.parse(**args)

    def test_unknown_duplicate_or_unbound_metadata_refuses(self):
        for key, value in (('budget_sha256', 'd' * 64), ('leaf', '../foreign'),
                           ('device', 0), ('inode', True), ('started_monotonic_nanos', 0)):
            packet = self.fixture(); packet['budget'][key] = value
            with self.subTest(key=key), self.assertRaises(OBSERVER.Incomplete):
                self.parse(packet)
        for packet in (dict(self.fixture(), trusted=True), dict(self.fixture(), instance='z' * 32)):
            with self.assertRaises(OBSERVER.Incomplete): self.parse(packet)
        payload = json.dumps(self.fixture()).encode().replace(b'"format":', b'"format":"forged","format":', 1)
        with self.assertRaises(OBSERVER.Incomplete): self.parse(payload=payload)


if __name__ == '__main__':
    unittest.main()

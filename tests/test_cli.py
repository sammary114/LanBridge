"""Unit tests for LanBridge CLI entry point and argument parsing."""

import unittest
from lanbridge.__main__ import build_parser


class TestCLIParser(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_default_args(self):
        args = self.parser.parse_args([])
        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.port, 8080)
        self.assertEqual(args.nickname, "LanBridge-Bot")
        self.assertFalse(args.web_only)
        self.assertFalse(args.no_web)
        self.assertFalse(args.import_native)

    def test_web_port_alias(self):
        args1 = self.parser.parse_args(["--web-port", "9090"])
        self.assertEqual(args1.port, 9090)

        args2 = self.parser.parse_args(["--port", "9091"])
        self.assertEqual(args2.port, 9091)

    def test_web_only_and_import_native(self):
        args = self.parser.parse_args(["--web-only", "--web-port", "8888", "--import-native"])
        self.assertTrue(args.web_only)
        self.assertEqual(args.port, 8888)
        self.assertTrue(args.import_native)


if __name__ == "__main__":
    unittest.main()

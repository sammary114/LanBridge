#!/usr/bin/env python3
"""LanBridge CLI Entry Point (__main__.py).

Allows one-click startup via `python -m lanbridge`:
Runs autonomous networking, UDP 9011 discovery, reliable ENet UDP 9012,
TCP file engines, and the modern Web UI & REST/WebSocket Gateway.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from lanbridge.client import LanBridgeClient
from lanbridge.web import start_web_server


def setup_logging(verbose: bool = False) -> None:
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lanbridge",
        description="LanBridge: Open-Source NeiWangTong (Nwt 3.4.3055) Autonomous Client & Gateway",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Web gateway bind host (default: 127.0.0.1)")
    parser.add_argument("--port", "--web-port", type=int, default=8080, dest="port", help="Web gateway HTTP port (default: 8080)")
    parser.add_argument("--nickname", default="LanBridge-Bot", help="Local nickname")
    parser.add_argument("--user-id", default=None, help="Local user ID (hex MD5)")
    parser.add_argument("--broadcast", default=None, help="Subnet broadcast IP (e.g. 192.168.1.255)")
    parser.add_argument("--import-native", action="store_true", help="Auto import config, groups, and shares from native Nwt installation")
    parser.add_argument("--native-dir", default=None, help="Path to native Nwt directory (default: C:\\Users\\Public\\Nwt)")
    parser.add_argument("--adopt-identity", action="store_true", help="Adopt native account UID, nickname, and signature")
    parser.add_argument("--no-web", action="store_true", help="Run in headless daemon mode without web gateway")
    parser.add_argument("--web-only", action="store_true", help="Run only the Web Gateway without binding UDP/TCP protocol network ports")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    return parser


async def main_async() -> None:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    client_kwargs = {
        "nickname": args.nickname,
        "auto_scan_on_start": not args.web_only,
    }
    if args.user_id:
        client_kwargs["user_id"] = args.user_id
    if args.broadcast:
        client_kwargs["broadcast_ip"] = args.broadcast

    client = LanBridgeClient(**client_kwargs)

    if args.import_native or args.native_dir or args.adopt_identity:
        res = client.import_from_native(
            nwt_dir=args.native_dir,
            apply_identity=args.adopt_identity,
        )
        if res.get("installed"):
            logging.info(
                "Imported from native Nwt (%s): %d groups, %d shares, %d subnets",
                res.get("nwt_dir"),
                res.get("groups_imported"),
                res.get("shares_imported"),
                len(res.get("subnets", [])),
            )

    if not args.web_only:
        await client.start()
    else:
        logging.info("Running in Web-Only mode: UDP/TCP networking listeners skipped.")

    runner = None
    if not args.no_web:
        runner = await start_web_server(client, host=args.host, port=args.port)
        mode_str = "Web-Only (No Protocol Ports)" if args.web_only else f"{client.local_ip}:{client.main_port}"
        print(f"\n=======================================================")
        print(f"  LanBridge Client & Web Gateway Ready!")
        print(f"  Web UI: http://{args.host}:{args.port}")
        print(f"  Node:   {client.nickname} ({client.user_id})")
        print(f"  Mode:   {mode_str}")
        print(f"=======================================================\n")

    try:
        while True:
            await asyncio.sleep(3600)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        if runner:
            await runner.cleanup()
        await client.stop()


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nLanBridge terminated by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()

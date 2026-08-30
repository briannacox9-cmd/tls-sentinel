from __future__ import annotations

import argparse
import json
import signal
import sys
import threading

from .application import Application
from .config import ConfigError, load
from .logging import configure
from .server import serve


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="tls-sentinel", description="Verify certificates presented by live TLS endpoints"
    )
    subcommands = root.add_subparsers(dest="command", required=True)
    for name in ("scan", "serve", "validate"):
        command = subcommands.add_parser(name)
        command.add_argument("--config", default="config.yaml", help="YAML inventory path")
        if name == "scan":
            command.add_argument("--json", action="store_true", help="emit machine-readable output")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logger = configure()
    try:
        config = load(args.config)
    except ConfigError as exc:
        logger.error("configuration_invalid", extra={"fields": {"error": str(exc)}})
        return 2
    if args.command == "validate":
        print(f"configuration valid: {len(config.endpoints)} endpoint(s)")
        return 0
    application = Application(config, logger)
    if args.command == "scan":
        try:
            results, events = application.run_scan()
        except Exception as exc:
            logger.error("scan_run_failed", extra={"fields": {"error": str(exc)}})
            return 1
        if args.json:
            print(
                json.dumps(
                    {"results": [r.to_dict() for r in results], "alerts": [e.to_dict() for e in events]}, indent=2
                )
            )
        else:
            _table(results)
            print(f"\n{len(results)} endpoint(s), {len(events)} alert(s)")
        return 1 if any(result.scan_error or not result.hostname_valid for result in results) else 0
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        serve(application, stop)
    except Exception as exc:
        logger.error("service_stopped", extra={"fields": {"error": str(exc)}})
        return 1
    return 0


def _table(results: list) -> None:
    rows = [("NAME", "ENDPOINT", "DAYS", "HOSTNAME", "CHANGED", "STATUS")]
    for result in results:
        status = result.scan_error or ("hostname mismatch" if not result.hostname_valid else "ok")
        days = "-" if result.days_remaining is None else f"{result.days_remaining:.1f}"
        rows.append(
            (
                result.name,
                f"{result.hostname}:{result.port}",
                days,
                str(result.hostname_valid),
                str(result.fingerprint_changed),
                status,
            )
        )
    widths = [max(len(str(row[index])) for row in rows) for index in range(len(rows[0]))]
    for row in rows:
        print("  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))


if __name__ == "__main__":
    sys.exit(main())

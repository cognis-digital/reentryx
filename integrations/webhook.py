#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import sys
import urllib.request
import urllib.error


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST reentryx JSON findings from stdin to a webhook URL.",
    )
    ap.add_argument("--url", required=True, help="Destination URL for the POST.")
    ap.add_argument(
        "--header", action="append", default=[], metavar="KEY: VALUE",
        help="Extra HTTP header to include; repeatable.",
    )
    ap.add_argument(
        "--timeout", type=int, default=15, metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 15).",
    )
    args = ap.parse_args()

    # Validate URL scheme early so the user gets a clear message.
    if not args.url.startswith(("http://", "https://")):
        print(
            f"error: --url must start with http:// or https://; got {args.url!r}",
            file=sys.stderr,
        )
        return 2

    if args.timeout <= 0:
        print(
            f"error: --timeout must be a positive integer; got {args.timeout}",
            file=sys.stderr,
        )
        return 2

    payload = sys.stdin.read().encode("utf-8")
    if not payload.strip():
        print(
            "warning: stdin is empty; sending an empty POST body",
            file=sys.stderr,
        )

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            print(
                f"error: --header value {h!r} must be in 'Key: Value' format",
                file=sys.stderr,
            )
            return 2
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(
            f"webhook error: HTTP {exc.code} {exc.reason} from {args.url}",
            file=sys.stderr,
        )
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook error: {exc.reason}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

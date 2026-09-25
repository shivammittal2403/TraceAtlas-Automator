from __future__ import annotations

import argparse
import json
import random
import signal
import time
from pathlib import Path

from .cloud_worker import CloudWorker, WorkerError


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="traceatlas-worker", description="TraceAtlas isolated queue worker")
    root.add_argument("--workspace", type=Path, default=Path("worker-cases"))
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("once", help="Claim and process at most one job")
    serve = sub.add_parser("serve", help="Continuously process allowlisted jobs")
    serve.add_argument("--poll-seconds", type=int, default=15)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        worker = CloudWorker(args.workspace)
        recovered = worker.recover_stale()
        if args.command == "once":
            print(json.dumps({"processed": worker.run_once(), "stale_recovered": recovered}))
            return 0
        poll = max(5, min(args.poll_seconds, 300))
        stopping = False

        def stop(_signum: int, _frame: object) -> None:
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        print(json.dumps({"status": "ready", "worker_id": worker.identity, "stale_recovered": recovered}))
        while not stopping:
            if not worker.run_once():
                time.sleep(poll + random.random() * min(5, poll / 2))
        return 0
    except WorkerError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Bounded child process for reviewed, allowlisted offline entry points.

Python audit restrictions are defense in depth, not an OS sandbox for arbitrary
plugins. Only the hash-pinned supplied modules are executable here.
"""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
from dataclasses import asdict, fields, is_dataclass, MISSING
from datetime import date, datetime
from enum import Enum
import hashlib
import importlib
import importlib.abc
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import sys
import types
from typing import Any, get_args, get_origin, get_type_hints, Union

MAX_BYTES = 8 * 1024 * 1024


class BoundedText(io.StringIO):
    def __init__(self):
        super().__init__()
        self.bytes_written = 0

    def write(self, value):
        self.bytes_written += len(value.encode("utf-8"))
        if self.bytes_written > MAX_BYTES:
            raise ValueError("Intelligence diagnostic output exceeded its limit")
        return super().write(value)


def json_default(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    raise TypeError("Unsupported intelligence output type")


def decode(value, annotation):
    """Construct only the dataclasses/enums named by an approved entry point."""
    origin, args = get_origin(annotation), get_args(annotation)
    if annotation is Any or annotation is inspect.Signature.empty:
        return value
    if origin in (Union, types.UnionType):
        if value is None and type(None) in args:
            return None
        for candidate in args:
            if candidate is type(None):
                continue
            try:
                return decode(value, candidate)
            except (ValueError, TypeError):
                continue
        raise ValueError("Value does not match the declared union")
    if origin in (list, tuple, set):
        if not isinstance(value, list) or len(value) > 500:
            raise ValueError("Declared arrays require at most 500 records")
        result = [decode(item, args[0] if args else Any) for item in value]
        return origin(result)
    if origin is dict:
        if not isinstance(value, dict):
            raise ValueError("Declared mappings require objects")
        return {decode(k, args[0] if args else Any): decode(v, args[1] if args else Any)
                for k, v in value.items()}
    if inspect.isclass(annotation) and issubclass(annotation, Enum):
        return annotation(value)
    if inspect.isclass(annotation) and is_dataclass(annotation):
        if not isinstance(value, dict):
            raise ValueError("Declared records require objects")
        declared = {field.name: field for field in fields(annotation) if field.init}
        if set(value) - set(declared):
            raise ValueError("Unknown fields in the declared record")
        hints = get_type_hints(annotation)
        result = {key: decode(item, hints.get(key, Any)) for key, item in value.items()}
        for key, field in declared.items():
            if key not in result and field.default is MISSING and field.default_factory is MISSING:
                raise ValueError("Missing required field: " + key)
        return annotation(**result)
    if annotation is datetime:
        if not isinstance(value, str):
            raise ValueError("Timestamps require ISO strings")
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    if annotation in (str, bool, int, float):
        if annotation is float and type(value) in (int, float):
            return float(value)
        if type(value) is not annotation:
            raise ValueError("Scalar does not match its declared type")
    return value


def restrict_process():
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    sys.dont_write_bytecode = True
    roots = [Path(sys.base_prefix).resolve(), Path(sys.prefix).resolve(),
             Path(__file__).resolve().parents[3]]
    for path in sys.path:
        if path and ("site-packages" in path or "dist-packages" in path):
            roots.append(Path(path).resolve())
    blocked = ("socket.", "subprocess.", "os.system", "os.exec", "os.spawn", "os.fork",
               "sqlite3.connect", "ctypes.", "resource.setrlimit")
    mutations = {"os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.chown",
                 "os.link", "os.symlink", "os.truncate", "os.chdir", "os.putenv"}

    def audit(event, args):
        if event.startswith(blocked) or event in mutations:
            raise PermissionError("Offline intelligence forbids " + event)
        if event == "open":
            path, mode, flags = args
            write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            if not isinstance(path, (str, bytes, os.PathLike)) or flags & write_flags:
                raise PermissionError("Offline intelligence forbids file writes/file descriptors")
            resolved = Path(os.fsdecode(path)).resolve()
            if not any(resolved.is_relative_to(root) for root in roots):
                raise PermissionError("Offline intelligence forbids reading external files")
    sys.addaudithook(audit)


class PinnedLoader(importlib.abc.Loader):
    """Compile the checked source bytes directly, ignoring mutable pyc caches."""
    def __init__(self, path, digest, package=False):
        self.path, self.digest, self.package = path, digest, package

    def create_module(self, spec):
        return None

    def is_package(self, fullname):
        return self.package

    def exec_module(self, module):
        source = self.path.read_bytes()
        if hashlib.sha256(source).hexdigest() != self.digest:
            raise ValueError("Pinned source changed before execution")
        module.__file__ = str(self.path)
        if self.package:
            module.__path__ = [str(self.path.parent)]
        exec(compile(source, str(self.path), "exec"), module.__dict__)


class PinnedModules(importlib.abc.MetaPathFinder):
    def __init__(self, manifest):
        self.root = Path(__file__).resolve().parent / "modules"
        self.identities = {row["id"]: row["file_sha256"] for row in manifest["modules"]}
        self.identities.update(manifest["support_files_sha256"])

    def find_spec(self, fullname, path=None, target=None):
        prefix = "traceatlas.addons.intelligence_v1.modules"
        if fullname == prefix:
            name, package = "__init__", True
        elif fullname.startswith(prefix + "."):
            name, package = fullname[len(prefix) + 1:], False
        else:
            return None
        if name not in self.identities:
            raise ImportError("Unregistered intelligence module")
        loader = PinnedLoader(self.root / (name + ".py"), self.identities[name], package)
        return importlib.util.spec_from_loader(fullname, loader, is_package=package)


def invoke(item, module, data):
    adapter = item["adapter"]
    entry = getattr(module, item["entry"])
    if adapter == "function":
        return entry(data)
    if adapter == "pipeline":
        # These upload pipelines have no configured source backend. Do not use
        # embedded sample corpora to manufacture a successful investigation.
        data = {**data, "sample": False} if "sample" in {f.name for f in fields(module.Case)} else data
        return entry(decode(data, module.Case))
    if adapter == "request":
        return entry().analyze(decode(data, getattr(module, item["request"])))
    if adapter == "employee":
        method = getattr(entry(), item["method"])
        if item["method"] in {"run_case", "analyze"}:
            return method(data)
        declared = inspect.signature(method).parameters
        allowed = set(declared)
        if set(data) - allowed:
            raise ValueError("Unknown employee input fields")
        return method(**data)
    if adapter == "journal":
        allowed = {"case_id", "objective", "scope", "questions", "records"}
        if set(data) - allowed:
            raise ValueError("Unknown journal input fields")
        journal = entry(data["case_id"], data["objective"], data.get("scope", "provided_records_only"))
        methods = ({"evidence": "add_evidence", "assets": "add_asset", "capacity_claims": "add_capacity_claim",
                    "outages": "add_outage", "incidents": "add_incident", "dependencies": "add_dependency",
                    "demand": "add_demand_observation", "prices": "add_price_observation"}
                   if item["id"] == "energyint" else
                   {"evidence": "add_evidence", "transactions": "add_transaction", "recoveries": "add_recovery",
                    "claims": "add_claim", "hypotheses": "add_hypothesis"})
        for key, rows in data.get("records", {}).items():
            if key not in methods or not isinstance(rows, list) or len(rows) > 500:
                raise ValueError("Unknown or oversized journal collection")
            method = getattr(journal, methods[key])
            for row in rows:
                inspect.signature(method).bind(**row)
                method(**row)
        return journal.analyze()
    if adapter == "plan":
        parsed = module.empty_parsed() if hasattr(module, "empty_parsed") else {}
        questions = module.default_questions(data) if hasattr(module, "default_questions") else data.get("questions", [])
        parameters = inspect.signature(entry).parameters
        values = {"payload": data, "questions": questions, "pirs": data.get("pirs", questions),
                  "sirs": data.get("sirs", []), "parsed": parsed}
        for name in parameters:
            values.setdefault(name, [] if name not in {"summary"} else {})
        return entry(**{key: values[key] for key in parameters})
    if adapter == "panel-plan":
        # Only pure planning helpers are called, without constructing a Tk window.
        questions = data.get("questions", [])
        if hasattr(entry, "_default_questions"):
            questions = entry._default_questions(None, data)
        policy = module.policy_screen(data) if hasattr(module, "policy_screen") else None
        return {"case_id": data["case_id"], "status": "PLANNING_ONLY", "questions": questions,
                "policy_screen": policy, "input": data,
                "next_action": "Use the standalone panel for approved local artifacts; provider execution is not graduated."}
    raise ValueError("Unsupported intelligence adapter")


def main():
    request = json.loads(sys.stdin.buffer.read(2 * 1024 * 1024 + 1))
    # Fixed source path, independent of CWD, PYTHONPATH and user input.
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from traceatlas.addons.intelligence_v1.registry import catalog, contract
    item = contract(request["module"])
    sys.meta_path.insert(0, PinnedModules(catalog()))
    restrict_process()
    with redirect_stdout(BoundedText()), redirect_stderr(BoundedText()):
        module = importlib.import_module("traceatlas.addons.intelligence_v1.modules." + item["id"])
        result = invoke(item, module, request["input"])
        output = json.dumps(result, default=json_default, ensure_ascii=False, allow_nan=False)
    if len(output.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Intelligence result exceeded its limit")
    sys.stdout.write(output)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # No raw input, credentials, paths, traceback or provider data in errors.
        sys.stderr.write(type(exc).__name__ + ": offline module could not accept this input\n")
        raise SystemExit(2)

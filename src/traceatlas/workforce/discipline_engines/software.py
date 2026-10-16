"""Dedicated supplied-record software and engineering intelligence analyzers.

All analyses concern the submitted records. No source code, commands, manifests,
network requests, or device operations are executed.
"""
from __future__ import annotations

import ast
from collections import Counter, defaultdict, deque
from datetime import datetime, time, timezone
import hashlib
import json
import math
import re
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from .common import AnalysisContext

LIMITATIONS = (
    "Results describe supplied records and static contracts, not observed runtime behavior.",
    "No code execution, external collection, package installation, or device operation occurred.",
)


def _groups(ctx, kinds, default):
    groups = {kind: [] for kind in kinds}
    for record in ctx.records:
        kind = record.data.get("kind", default)
        if not isinstance(kind, str) or kind not in groups:
            ctx.issue(record, "UNSUPPORTED_RECORD_KIND", "Unsupported record kind for this discipline")
        else:
            groups[kind].append(record)
    return groups


def _text(ctx, record, key, required=True):
    value = record.data.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        ctx.issue(record, "INVALID_FIELD", key + " must be a nonempty string")
        return None
    return value.strip()


def _number(ctx, record, key, required=True):
    value = record.data.get(key)
    if value is None and not required:
        return None
    try:
        valid = not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        ctx.issue(record, "INVALID_NUMBER", key + " must be a finite number")
        return None
    return value


def _boolean(ctx, record, key):
    value = record.data.get(key)
    if value is not None and not isinstance(value, bool):
        ctx.issue(record, "INVALID_BOOLEAN", key + " must be true or false")
        return None
    return value


def _strings(ctx, record, key):
    value = record.data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        ctx.issue(record, "INVALID_ARRAY", key + " must contain nonempty strings")
        return []
    return list(dict.fromkeys(item.strip() for item in value))


def _when(ctx, record, value, field, end_of_date=False):
    if value is None:
        return None
    if not isinstance(value, str):
        ctx.issue(record, "INVALID_TIMESTAMP", field + " must be an ISO timestamp")
        return None
    try:
        if end_of_date and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return datetime.combine(datetime.fromisoformat(value).date(), time.max, timezone.utc)
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError()
        return result.astimezone(timezone.utc)
    except ValueError:
        ctx.issue(record, "INVALID_TIMESTAMP", field + " requires an ISO timestamp with timezone")
        return None


def _finish(ctx, metrics=None, artifacts=None, extra=()):
    return ctx.output(metrics=metrics or {}, artifacts=artifacts or {}, limitations=(*LIMITATIONS, *extra))


def _graph(nodes, edges):
    nodes = set(nodes) | {node for edge in edges for node in edge}
    adjacency = {node: set() for node in nodes}
    reverse = {node: set() for node in nodes}
    for left, right in edges:
        adjacency[left].add(right)
        reverse[right].add(left)
    visited, order = set(), []
    for start in sorted(nodes):
        if start in visited:
            continue
        stack = [(start, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                order.append(node)
            elif node not in visited:
                visited.add(node)
                stack.append((node, True))
                stack.extend((child, False) for child in sorted(adjacency[node], reverse=True) if child not in visited)
    visited, cycles = set(), []
    for start in reversed(order):
        if start in visited:
            continue
        component, stack = [], [start]
        visited.add(start)
        while stack:
            node = stack.pop()
            component.append(node)
            for parent in reverse[node]:
                if parent not in visited:
                    visited.add(parent)
                    stack.append(parent)
        if len(component) > 1 or start in adjacency[start]:
            cycles.append(sorted(component))
    return adjacency, sorted(cycles)


def _repository_url(ctx, record, value):
    if not isinstance(value, str):
        ctx.issue(record, "INVALID_REPOSITORY_URL", "Repository URL must be a string")
        return None
    value = value.strip()
    ssh = re.fullmatch(r"git@([^:/\s]+):([^\s]+)", value)
    if ssh:
        value = "https://" + ssh.group(1) + "/" + ssh.group(2)
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "ssh"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError()
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        path = parsed.path.strip("/").removesuffix(".git")
        parts = path.split("/")
        if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts):
            raise ValueError()
        if host in {"github.com", "bitbucket.org"}:
            if len(parts) != 2:
                raise ValueError()
            path = path.lower()
        return "https://" + host + ((":" + str(parsed.port)) if parsed.port else "") + "/" + path
    except (ValueError, UnicodeError):
        ctx.issue(record, "INVALID_REPOSITORY_URL", "A repository URL without credentials is required")
        return None


def repoint(ctx: AnalysisContext):
    groups = _groups(ctx, {"repository", "commit", "branch"}, "repository")
    repositories, commit_groups, branches = {}, defaultdict(list), []
    for record in groups["repository"]:
        url = _repository_url(ctx, record, record.data.get("url"))
        if url:
            repositories.setdefault(url, []).append(record.record_id)
    for record in groups["commit"]:
        url = _repository_url(ctx, record, record.data.get("repository_url"))
        commit = _text(ctx, record, "commit_id")
        if not url or not commit:
            continue
        if url not in repositories:
            ctx.issue(record, "UNDECLARED_REPOSITORY", "Commit repository is absent from the repository inventory")
        fingerprint = {key: record.data.get(key) for key in ("parent_ids", "author_id", "message_sha256", "tree_sha256")}
        commit_groups[(url, commit)].append((record, fingerprint))
    conflicts = 0
    for (url, commit), rows in commit_groups.items():
        if len({json.dumps(data, sort_keys=True) for _, data in rows}) > 1:
            conflicts += 1
            ctx.finding("COMMIT_METADATA_CONFLICT", "The same supplied commit ID has conflicting metadata",
                        [record.record_id for record, _ in rows], {"repository": url, "commit_id": commit})
    for record in groups["branch"]:
        url = _repository_url(ctx, record, record.data.get("repository_url"))
        name = _text(ctx, record, "name")
        protected = _boolean(ctx, record, "protected")
        if url and name:
            branches.append({"record_id": record.record_id, "repository": url, "name": name, "protected": protected})
            if protected is False:
                ctx.finding("UNPROTECTED_BRANCH_DECLARED", "A supplied branch record declares protection disabled",
                            [record.record_id], {"repository": url, "branch": name})
            elif protected is None:
                ctx.issue(record, "PROTECTION_UNKNOWN", "Branch protection was not established by this record")
    return _finish(ctx, {"repositories": len(repositories), "unique_commits": len(commit_groups),
                         "conflicting_commit_ids": conflicts, "branches": len(branches)},
                   {"repositories": [{"url": url, "record_ids": ids} for url, ids in sorted(repositories.items())],
                    "branches": branches})


def _version(value):
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?", value.strip())
    if not match:
        return None
    if any(len(match.group(index) or "") > 12 for index in (1, 2, 3)):
        return None
    major, minor, patch = (int(match.group(index) or 0) for index in (1, 2, 3))
    prerelease = match.group(4)
    parts = []
    for part in prerelease.split(".") if prerelease else []:
        if part.isdigit():
            if len(part) > 12 or (len(part) > 1 and part.startswith("0")):
                return None
            parts.append((0, int(part)))
        else:
            parts.append((1, part))
    return major, minor, patch, 0 if prerelease else 1, tuple(parts)


def _in_range(version, expression):
    parsed = _version(version)
    if parsed is None or not isinstance(expression, str) or not expression.strip():
        return None
    alternatives = []
    for alternative in expression.split("||"):
        outcomes = []
        for term in re.split(r",\s*|\s+(?=[<>!=])", alternative.strip()):
            match = re.fullmatch(r"(==|!=|>=|<=|>|<|=)?\s*(\S+)", term)
            target = _version(match.group(2)) if match else None
            if target is None:
                outcomes.append(None)
                continue
            operator = match.group(1) or "=="
            outcomes.append({"==": parsed == target, "=": parsed == target, "!=": parsed != target,
                             ">=": parsed >= target, "<=": parsed <= target,
                             ">": parsed > target, "<": parsed < target}[operator])
        alternatives.append(False if False in outcomes else None if None in outcomes else True)
    return True if True in alternatives else None if None in alternatives else False


def _package_key(ctx, record):
    ecosystem, name = _text(ctx, record, "ecosystem"), _text(ctx, record, "name")
    if not ecosystem or not name:
        return None
    ecosystem = ecosystem.lower()
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem in {"npm", "nuget"}:
        name = name.lower()
    return ecosystem, name


def packageint(ctx: AnalysisContext):
    groups = _groups(ctx, {"package", "advisory"}, "package")
    packages, advisories, matches, identities = [], [], [], defaultdict(list)
    for record in groups["package"]:
        key = _package_key(ctx, record)
        version = _text(ctx, record, "version")
        registry = _text(ctx, record, "registry", required=False)
        digest = _text(ctx, record, "sha256", required=False)
        if digest and not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            ctx.issue(record, "INVALID_HASH", "sha256 must contain 64 hexadecimal characters")
            digest = None
        if key:
            item = {"record_id": record.record_id, "ecosystem": key[0], "name": key[1],
                    "version": version, "registry": registry, "sha256": digest.lower() if digest else None}
            packages.append(item)
            identities[(key, version, registry)].append(item)
    for record in groups["advisory"]:
        key = _package_key(ctx, record)
        expression, advisory_id = _text(ctx, record, "affected_versions"), _text(ctx, record, "advisory_id")
        if key and expression and advisory_id:
            advisories.append((record, key, expression, advisory_id))
    for package in packages:
        for record, key, expression, advisory_id in advisories:
            if (package["ecosystem"], package["name"]) != key:
                continue
            affected = _in_range(package["version"], expression)
            state = "AFFECTED_CANDIDATE" if affected is True else "OUTSIDE_SUPPLIED_RANGE" if affected is False else "UNKNOWN_VERSION_RANGE"
            matches.append({"package_record_id": package["record_id"], "advisory_record_id": record.record_id,
                            "advisory_id": advisory_id, "state": state})
            if affected is True:
                ctx.finding("SUPPLIED_ADVISORY_MATCH", "A supplied package version falls within a supplied advisory range",
                            [package["record_id"], record.record_id], {"advisory_id": advisory_id, "package": package["name"]})
            elif affected is None:
                ctx.issue(record, "UNSUPPORTED_VERSION_RANGE", "The numeric-release/SemVer comparator subset cannot decide this range")
    for rows in identities.values():
        if len({item["sha256"] for item in rows if item["sha256"]}) > 1:
            ctx.finding("PACKAGE_ARTIFACT_HASH_CONFLICT", "One supplied package/version/registry identity has different SHA-256 hashes",
                        [item["record_id"] for item in rows])
    return _finish(ctx, {"package_records": len(packages), "advisory_records": len(advisories),
                         "advisory_comparisons": len(matches)},
                   {"packages": packages, "advisory_matches": matches},
                   ("Version matching supports numeric releases, SemVer prereleases, comparison conjunctions and ||; other range syntax remains unknown.",))


def sbomint(ctx: AnalysisContext):
    groups = _groups(ctx, {"sbom"}, "sbom")
    components, dangling, cycle_count, formats = [], [], 0, Counter()
    for record in groups["sbom"]:
        document = record.data.get("document")
        if not isinstance(document, dict):
            ctx.issue(record, "INVALID_SBOM", "document must be a supplied SBOM object")
            continue
        cyclone = document.get("bomFormat") == "CycloneDX"
        spdx = isinstance(document.get("spdxVersion"), str) and document["spdxVersion"].startswith("SPDX-")
        if not cyclone and not spdx:
            ctx.issue(record, "UNSUPPORTED_SBOM_FORMAT", "Supply a CycloneDX or SPDX JSON document")
            continue
        formats["CycloneDX" if cyclone else "SPDX"] += 1
        rows = document.get("components" if cyclone else "packages", [])
        if not isinstance(rows, list):
            ctx.issue(record, "INVALID_COMPONENTS", "SBOM components must be an array")
            continue
        refs, edges = {}, []
        pending = list(rows)
        while pending:
            component = pending.pop()
            if not isinstance(component, dict):
                ctx.issue(record, "INVALID_COMPONENT", "An SBOM component is not an object")
                continue
            ref = component.get("bom-ref" if cyclone else "SPDXID")
            if not isinstance(ref, str) or not ref:
                ctx.issue(record, "COMPONENT_REFERENCE_MISSING", "A component lacks its document reference")
                continue
            version = component.get("version" if cyclone else "versionInfo")
            item = {"document_record_id": record.record_id, "ref": ref, "name": component.get("name"), "version": version}
            if ref in refs and refs[ref] != item:
                ctx.finding("SBOM_COMPONENT_CONFLICT", "A supplied SBOM repeats a component reference with conflicting metadata",
                            [record.record_id], {"ref": ref})
            refs.setdefault(ref, item)
            components.append(item)
            if not isinstance(version, str) or not version:
                ctx.issue(record, "COMPONENT_VERSION_MISSING", "Component " + ref + " lacks a version")
            children = component.get("components", []) if cyclone else []
            if isinstance(children, list):
                pending.extend(children)
            else:
                ctx.issue(record, "INVALID_COMPONENTS", "Nested components must be an array")
        relations = document.get("dependencies" if cyclone else "relationships", [])
        if not isinstance(relations, list):
            ctx.issue(record, "INVALID_DEPENDENCIES", "SBOM relationships must be an array")
            continue
        for relation in relations:
            if not isinstance(relation, dict):
                ctx.issue(record, "INVALID_DEPENDENCY", "An SBOM relationship is not an object")
                continue
            if cyclone:
                left, targets = relation.get("ref"), relation.get("dependsOn", [])
            elif relation.get("relationshipType") == "DEPENDS_ON":
                left, targets = relation.get("spdxElementId"), [relation.get("relatedSpdxElement")]
            elif relation.get("relationshipType") == "DEPENDENCY_OF":
                left, targets = relation.get("relatedSpdxElement"), [relation.get("spdxElementId")]
            else:
                continue
            if not isinstance(left, str) or not isinstance(targets, list) or any(not isinstance(target, str) for target in targets):
                ctx.issue(record, "INVALID_DEPENDENCY", "Dependency endpoints must be document reference strings")
                continue
            for target in targets:
                edges.append((left, target))
                if left not in refs or target not in refs:
                    dangling.append({"document_record_id": record.record_id, "from": left, "to": target})
                    ctx.finding("SBOM_DANGLING_REFERENCE", "An SBOM dependency references an undeclared component",
                                [record.record_id], {"from": left, "to": target})
        _, cycles = _graph(refs, edges)
        cycle_count += len(cycles)
        for cycle in cycles:
            ctx.finding("SBOM_DEPENDENCY_CYCLE", "The supplied SBOM dependency graph contains a cyclic component",
                        [record.record_id], {"component_refs": cycle})
    return _finish(ctx, {"documents_by_format": dict(formats), "component_records": len(components),
                         "dangling_edges": len(dangling), "cyclic_components": cycle_count},
                   {"components": components, "dangling_dependencies": dangling})


def dependencyint(ctx: AnalysisContext):
    groups = _groups(ctx, {"component", "dependency"}, "dependency")
    nodes, edge_records, roots, ambiguous = {}, [], set(), set()
    for record in groups["component"]:
        node = _text(ctx, record, "component_id")
        if not node:
            continue
        if node in nodes and nodes[node][1] != record.data.get("version"):
            ambiguous.add(node)
            ctx.finding("COMPONENT_VERSION_CONFLICT", "A dependency node has conflicting supplied versions",
                        [nodes[node][0].record_id, record.record_id], {"component_id": node})
        nodes.setdefault(node, (record, record.data.get("version")))
        if _boolean(ctx, record, "root") is True:
            roots.add(node)
    for record in groups["dependency"]:
        left, right = _text(ctx, record, "from"), _text(ctx, record, "to")
        if left and right:
            edge_records.append((left, right, record))
            if left not in nodes or right not in nodes:
                ctx.issue(record, "UNRESOLVED_COMPONENT", "Dependency endpoints are absent from the component inventory")
            constraint = _text(ctx, record, "constraint", required=False)
            if constraint and right in nodes:
                match = None if right in ambiguous else _in_range(nodes[right][1], constraint)
                if match is False:
                    ctx.finding("DEPENDENCY_CONSTRAINT_MISMATCH", "A supplied resolved version violates its declared dependency constraint",
                                [record.record_id, nodes[right][0].record_id], {"component_id": right, "constraint": constraint})
                elif match is None:
                    ctx.issue(record, "UNSUPPORTED_VERSION_RANGE", "The supplied dependency constraint cannot be decided")
    edges = [(left, right) for left, right, _ in edge_records]
    adjacency, cycles = _graph(nodes, edges)
    roots_declared = bool(roots)
    if not roots:
        targets = {right for _, right in edges}
        roots = set(adjacency) - targets
    depths, queue = {root: 0 for root in roots}, deque(sorted(roots))
    while queue:
        node = queue.popleft()
        for child in sorted(adjacency[node]):
            if child not in depths:
                depths[child] = depths[node] + 1
                queue.append(child)
    for cycle in cycles:
        related = [record.record_id for left, right, record in edge_records if left in cycle and right in cycle]
        ctx.finding("DEPENDENCY_CYCLE", "The supplied dependency graph contains a cyclic component",
                    related, {"component_ids": cycle})
    return _finish(ctx, {"declared_components": len(nodes), "edges": len(edges), "cyclic_components": len(cycles),
                         "reachable_components": len(depths), "transitive_components": sum(depth > 1 for depth in depths.values())},
                   {"roots": sorted(roots), "roots_method": "SUPPLIED_ROOT_FLAGS" if roots_declared else "ZERO_INDEGREE",
                    "minimum_depth": dict(sorted(depths.items())), "cyclic_components": cycles,
                    "unreachable_components": sorted(set(adjacency) - set(depths))})


def codeint(ctx: AnalysisContext):
    groups = _groups(ctx, {"source_file"}, "source_file")
    files, imports, symbols, fingerprints = [], [], [], defaultdict(list)
    dangerous = {"eval", "exec", "pickle.loads", "pickle.load", "marshal.loads"}
    for record in groups["source_file"]:
        path = _text(ctx, record, "path")
        content = record.data.get("content")
        if not path or not isinstance(content, str):
            ctx.issue(record, "INVALID_SOURCE", "Source content must be supplied text")
            continue
        language = record.data.get("language", "python")
        if not isinstance(language, str) or language.lower() not in {"python", "py"}:
            ctx.issue(record, "UNSUPPORTED_LANGUAGE", "This static analyzer currently accepts Python source")
            continue
        digest = hashlib.sha256(content.encode()).hexdigest()
        fingerprints[digest].append(record.record_id)
        try:
            tree = ast.parse(content, filename="<supplied-record>")
        except (SyntaxError, ValueError, RecursionError) as exc:
            ctx.issue(record, "PYTHON_SYNTAX_ERROR", "Supplied Python source could not be parsed at line " + str(getattr(exc, "lineno", None)))
            continue
        aliases, calls = {}, 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
                    imports.append({"record_id": record.record_id, "module": alias.name, "line": node.lineno})
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = (node.module or "") + "." + alias.name
                    imports.append({"record_id": record.record_id, "module": node.module, "line": node.lineno})
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbols.append({"record_id": record.record_id, "name": node.name, "line": node.lineno, "kind": type(node).__name__})
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                calls += 1
                names, current = [], node.func
                while isinstance(current, ast.Attribute):
                    names.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    names.append(aliases.get(current.id, current.id))
                symbol = ".".join(reversed(names))
                shell = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
                if symbol in dangerous or (symbol.startswith("subprocess.") and shell):
                    ctx.finding("STATIC_SENSITIVE_CALL", "Supplied source contains a call requiring security review",
                                [record.record_id], {"path": path, "line": node.lineno, "symbol": symbol, "shell": shell})
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and re.search(r"password|passwd|secret|api_?key|access_?token", target.id, re.I):
                        if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                            ctx.finding("STATIC_SECRET_CANDIDATE", "A sensitive-looking variable has a literal string assignment",
                                        [record.record_id], {"path": path, "line": node.lineno,
                                        "value_sha256": hashlib.sha256(value.value.encode()).hexdigest(), "value_redacted": True})
        files.append({"record_id": record.record_id, "path": path, "sha256": digest, "call_count": calls})
    duplicates = [ids for ids in fingerprints.values() if len(ids) > 1]
    for ids in duplicates:
        ctx.finding("IDENTICAL_SOURCE_CONTENT", "Supplied source files have identical bytes", ids)
    return _finish(ctx, {"parsed_files": len(files), "imports": len(imports), "symbols": len(symbols),
                         "duplicate_content_groups": len(duplicates)},
                   {"files": files, "imports": imports, "symbols": symbols},
                   ("Static call names and literal candidates do not establish reachability, credential validity, or exploitation.",))


def devint(ctx: AnalysisContext):
    groups = _groups(ctx, {"contribution", "release"}, "contribution")
    contributions, commit_groups, releases = Counter(), defaultdict(list), defaultdict(list)
    for record in groups["contribution"]:
        developer, repository = _text(ctx, record, "developer_id"), _text(ctx, record, "repository_id")
        contribution = _text(ctx, record, "contribution_id")
        if developer and repository and contribution:
            commit_groups[(repository, contribution)].append((record, developer))
    commits, ambiguous = [], []
    for (repository, contribution), rows in commit_groups.items():
        if len({developer for _, developer in rows}) > 1:
            ambiguous.append({"repository_id": repository, "contribution_id": contribution})
            ctx.finding("CONTRIBUTION_ATTRIBUTION_CONFLICT", "One supplied contribution ID names different contributors",
                        [record.record_id for record, _ in rows], {"repository_id": repository, "contribution_id": contribution})
        else:
            commits.append(rows[0])
            contributions[rows[0][1]] += 1
    intervals = {}
    for record in groups["release"]:
        repository = _text(ctx, record, "repository_id")
        released = _when(ctx, record, record.data.get("released_at"), "released_at")
        if not released:
            ctx.issue(record, "RELEASE_TIME_MISSING", "Release cadence requires released_at")
        elif released > ctx.as_of:
            ctx.issue(record, "FUTURE_RELEASE_RECORD", "A release timestamp lies after the supplied analysis time")
        elif repository:
            releases[repository].append((released, record.record_id))
    for repository, rows in releases.items():
        times = sorted({instant for instant, _ in rows})
        intervals[repository] = [(right - left).total_seconds() / 86400 for left, right in zip(times, times[1:])]
    total = sum(contributions.values())
    required, cumulative = 0, 0
    for count in sorted(contributions.values(), reverse=True):
        if cumulative >= total / 2:
            break
        cumulative += count
        required += 1
    if total and max(contributions.values()) / total > 0.5:
        dominant = max(contributions, key=contributions.get)
        ctx.finding("SUPPLIED_CONTRIBUTION_CONCENTRATION", "One contributor accounts for over half of unambiguously attributed supplied contributions",
                    [record.record_id for record, developer in commits if developer == dominant],
                    {"developer_id": dominant, "count": contributions[dominant], "total": total})
    return _finish(ctx, {"unique_contribution_ids": len(commit_groups), "unambiguous_contributions": total,
                         "contributors": len(contributions), "contributors_for_half_supplied_contributions": required,
                         "method": "UNIQUE_REPOSITORY_CONTRIBUTION_IDS_EXCLUDING_CONFLICTED_ATTRIBUTION"},
                   {"contribution_counts": dict(sorted(contributions.items())), "release_intervals_days": intervals,
                    "excluded_ambiguous_contributions": ambiguous},
                   ("Contributor handles do not establish real-world identity, employment, competence, or an operational bus factor.",))


def cicdint(ctx: AnalysisContext):
    groups = _groups(ctx, {"workflow"}, "workflow")
    jobs_total, actions, broad, cyclic = 0, [], 0, 0
    for record in groups["workflow"]:
        workflow = _text(ctx, record, "workflow_id")
        jobs = record.data.get("jobs")
        if not workflow or not isinstance(jobs, list):
            ctx.issue(record, "INVALID_WORKFLOW", "A workflow requires a jobs array")
            continue
        permissions = record.data.get("permissions", {})
        if permissions == "write-all" or (isinstance(permissions, dict) and any(value == "write" for value in permissions.values())):
            broad += 1
            ctx.finding("WORKFLOW_WRITE_PERMISSIONS", "The supplied workflow declares write-capable permissions",
                        [record.record_id], {"workflow_id": workflow})
        triggers = _strings(ctx, record, "triggers")
        ids, edges = set(), []
        for job in jobs:
            if not isinstance(job, dict) or not isinstance(job.get("job_id"), str) or not job["job_id"]:
                ctx.issue(record, "INVALID_JOB", "Jobs require a string job_id")
                continue
            job_id = job["job_id"]
            if job_id in ids:
                ctx.issue(record, "DUPLICATE_JOB_ID", "Workflow job IDs must be unique")
            ids.add(job_id)
            jobs_total += 1
            needs = job.get("needs", [])
            if isinstance(needs, str):
                needs = [needs]
            if not isinstance(needs, list) or any(not isinstance(item, str) for item in needs):
                ctx.issue(record, "INVALID_JOB_DEPENDENCIES", "Job needs must contain job IDs")
                needs = []
            edges.extend((job_id, dependency) for dependency in needs)
            job_permissions = job.get("permissions", {})
            if job_permissions == "write-all" or (isinstance(job_permissions, dict) and any(value == "write" for value in job_permissions.values())):
                ctx.finding("JOB_WRITE_PERMISSIONS", "A supplied job declares write-capable permissions",
                            [record.record_id], {"workflow_id": workflow, "job_id": job_id})
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                ctx.issue(record, "INVALID_STEPS", "Job steps must be an array")
                continue
            for index, step in enumerate(steps):
                if not isinstance(step, dict):
                    ctx.issue(record, "INVALID_STEP", "A workflow step is not an object")
                    continue
                uses = step.get("uses")
                if uses is not None:
                    if not isinstance(uses, str):
                        ctx.issue(record, "INVALID_ACTION_REFERENCE", "Step uses must be a string")
                        continue
                    pinned = uses.startswith("./") or bool(re.search(r"@[0-9a-fA-F]{40}$", uses)) or bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", uses))
                    actions.append({"record_id": record.record_id, "job_id": job_id, "step": index, "reference": uses, "immutable_reference": pinned})
                    if not pinned:
                        ctx.finding("MUTABLE_ACTION_REFERENCE", "A supplied remote workflow reference lacks an immutable digest",
                                    [record.record_id], {"job_id": job_id, "step": index, "reference": uses})
                values = step.get("with", {})
                ref = values.get("ref", "") if isinstance(values, dict) else ""
                if "pull_request_target" in triggers and isinstance(ref, str) and "pull_request.head" in ref:
                    ctx.finding("PR_TARGET_UNTRUSTED_CHECKOUT_CANDIDATE", "A privileged pull-request trigger references pull-request head content",
                                [record.record_id], {"job_id": job_id, "step": index})
                run = step.get("run")
                if isinstance(run, str) and re.search(r"\b(?:curl|wget)\b[\s\S]*\|\s*(?:sh|bash)\b", run):
                    ctx.finding("DOWNLOADED_SCRIPT_EXECUTION_DECLARED", "A supplied workflow step pipes downloaded content into a shell",
                                [record.record_id], {"job_id": job_id, "step": index, "command_sha256": hashlib.sha256(run.encode()).hexdigest()})
        for left, right in edges:
            if right not in ids:
                ctx.issue(record, "UNRESOLVED_JOB_DEPENDENCY", "Job " + left + " needs an undeclared job")
        _, cycles = _graph(ids, edges)
        cyclic += len(cycles)
        for cycle in cycles:
            ctx.finding("WORKFLOW_JOB_CYCLE", "Workflow job dependencies are cyclic",
                        [record.record_id], {"job_ids": cycle})
    return _finish(ctx, {"jobs": jobs_total, "action_references": len(actions),
                         "workflow_write_permission_records": broad, "cyclic_job_groups": cyclic},
                   {"action_references": actions})


def appint(ctx: AnalysisContext):
    groups = _groups(ctx, {"application", "route"}, "application")
    applications, routes = {}, []
    for record in groups["application"]:
        app = _text(ctx, record, "application_id")
        if not app:
            continue
        version = _text(ctx, record, "version", required=False)
        public, authenticated = _boolean(ctx, record, "public"), _boolean(ctx, record, "authentication_required")
        applications.setdefault(app, []).append({"record_id": record.record_id, "version": version,
                                                "public": public, "authentication_required": authenticated})
        if public is True and authenticated is False:
            ctx.finding("PUBLIC_APP_WITHOUT_AUTH_DECLARED", "A supplied application record declares public access without authentication",
                        [record.record_id], {"application_id": app})
        support = _when(ctx, record, record.data.get("support_until"), "support_until", end_of_date=True)
        if support and support < ctx.as_of:
            ctx.finding("APPLICATION_SUPPORT_ENDED", "A supplied support date precedes the analysis time",
                        [record.record_id], {"application_id": app, "support_until": support.isoformat()})
    for record in groups["route"]:
        app, path, method = _text(ctx, record, "application_id"), _text(ctx, record, "path"), _text(ctx, record, "method")
        authenticated = _boolean(ctx, record, "authentication_required")
        public = _boolean(ctx, record, "public")
        if not app or not path or not method:
            continue
        if app not in applications:
            ctx.issue(record, "UNDECLARED_APPLICATION", "A route references an application absent from the inventory")
        item = {"record_id": record.record_id, "application_id": app, "path": path,
                "method": method.upper(), "public": public, "authentication_required": authenticated}
        routes.append(item)
        if public is True and authenticated is False:
            ctx.finding("PUBLIC_ROUTE_WITHOUT_AUTH_DECLARED", "A supplied application route declares public access without authentication",
                        [record.record_id], {"application_id": app, "path": path, "method": method.upper()})
        elif authenticated is None:
            ctx.issue(record, "ROUTE_AUTH_UNKNOWN", "Route authentication requirements were not supplied")
    return _finish(ctx, {"applications": len(applications), "routes": len(routes),
                         "routes_with_auth_requirement": sum(item["authentication_required"] is True for item in routes)},
                   {"application_inventory": applications, "route_auth_matrix": routes},
                   ("An intentionally public application or route can be legitimate; these records do not verify a deployed vulnerability.",))


def mobileint(ctx: AnalysisContext):
    groups = _groups(ctx, {"mobile_manifest"}, "mobile_manifest")
    manifests, sensitive = [], {"READ_CONTACTS", "READ_SMS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG"}
    android = "{http://schemas.android.com/apk/res/android}"
    for record in groups["mobile_manifest"]:
        platform = _text(ctx, record, "platform")
        if platform and platform.lower() == "android":
            content = record.data.get("content")
            if not isinstance(content, str) or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.I):
                ctx.issue(record, "UNSAFE_OR_INVALID_XML", "Supply manifest XML without DTD or entity declarations")
                continue
            try:
                root = ET.fromstring(content)
            except ET.ParseError:
                ctx.issue(record, "INVALID_MANIFEST_XML", "Android manifest XML could not be parsed")
                continue
            if root.tag != "manifest":
                ctx.issue(record, "INVALID_MANIFEST_ROOT", "Android XML must have a manifest root")
                continue
            permissions = sorted({node.get(android + "name", "") for node in root.findall("uses-permission") if node.get(android + "name")})
            sdk = root.find("uses-sdk")
            sdk_value = sdk.get(android + "targetSdkVersion") if sdk is not None else None
            target = int(sdk_value) if isinstance(sdk_value, str) and sdk_value.isdigit() and len(sdk_value) < 5 else None
            app = root.find("application")
            exported = []
            if app is not None:
                for attribute, finding in (("debuggable", "ANDROID_DEBUGGABLE_DECLARED"), ("usesCleartextTraffic", "ANDROID_CLEARTEXT_DECLARED")):
                    if app.get(android + attribute) == "true":
                        ctx.finding(finding, "Android manifest explicitly enables " + attribute, [record.record_id])
                for node in list(app):
                    if node.tag not in {"activity", "activity-alias", "service", "receiver", "provider"}:
                        continue
                    declared = node.get(android + "exported")
                    has_filter = node.find("intent-filter") is not None
                    if declared is None and has_filter and target is not None and target >= 31:
                        ctx.issue(record, "ANDROID_EXPORTED_DECLARATION_MISSING", "A component with an intent filter lacks required exported metadata")
                    effective = declared == "true" or (declared is None and has_filter and target is not None and target < 31)
                    if effective:
                        exported.append(node.get(android + "name", "UNNAMED"))
                        if not node.get(android + "permission"):
                            ctx.finding("ANDROID_EXPORTED_WITHOUT_COMPONENT_PERMISSION", "A supplied manifest exports a component without a component permission",
                                        [record.record_id], {"component": node.get(android + "name"), "component_type": node.tag})
            manifests.append({"record_id": record.record_id, "platform": "android", "package": root.get("package"),
                              "target_sdk": target, "permissions": permissions, "exported_components": exported})
            for permission in permissions:
                if permission.rsplit(".", 1)[-1] in sensitive:
                    ctx.finding("ANDROID_SENSITIVE_PERMISSION_DECLARED", "A supplied Android manifest requests a sensitive permission",
                                [record.record_id], {"permission": permission})
        elif platform and platform.lower() == "ios":
            document = record.data.get("document")
            if not isinstance(document, dict):
                ctx.issue(record, "INVALID_IOS_PLIST_OBJECT", "Supply the decoded Info.plist as a JSON object")
                continue
            ats = document.get("NSAppTransportSecurity", {})
            if not isinstance(ats, dict):
                ctx.issue(record, "INVALID_ATS_OBJECT", "NSAppTransportSecurity must be an object")
                ats = {}
            if ats.get("NSAllowsArbitraryLoads") is True:
                ctx.finding("IOS_ARBITRARY_LOADS_DECLARED", "A supplied Info.plist enables arbitrary network loads", [record.record_id])
            privacy_keys = sorted(key for key in document if key.startswith("NS") and key.endswith("UsageDescription"))
            manifests.append({"record_id": record.record_id, "platform": "ios", "bundle_id": document.get("CFBundleIdentifier"),
                              "privacy_usage_keys": privacy_keys})
        elif platform:
            ctx.issue(record, "UNSUPPORTED_MOBILE_PLATFORM", "Only Android manifest XML and decoded iOS Info.plist objects are supported")
    return _finish(ctx, {"manifests_analyzed": len(manifests)}, {"manifests": manifests},
                   ("Manifest declarations alone do not establish runtime permission grants, data access, or malicious behavior.",))


def iotint(ctx: AnalysisContext):
    groups = _groups(ctx, {"device", "firmware", "telemetry"}, "device")
    devices, firmware, telemetry = {}, defaultdict(list), defaultdict(list)
    for record in groups["device"]:
        device = _text(ctx, record, "device_id")
        if not device:
            continue
        if device in devices:
            ctx.issue(record, "DUPLICATE_DEVICE_ID", "Device ID appears more than once; records require reconciliation")
        devices.setdefault(device, record)
        for field in ("secure_boot", "updates_signed"):
            if _boolean(ctx, record, field) is False:
                ctx.finding("IOT_CONTROL_DISABLED_DECLARED", "A supplied device record declares " + field + " disabled",
                            [record.record_id], {"device_id": device, "control": field})
        support = _when(ctx, record, record.data.get("support_until"), "support_until", end_of_date=True)
        if support and support < ctx.as_of:
            ctx.finding("IOT_SUPPORT_ENDED", "A supplied device support date precedes the analysis time",
                        [record.record_id], {"device_id": device})
    for record in groups["firmware"]:
        device, version = _text(ctx, record, "device_id"), _text(ctx, record, "version")
        released = _when(ctx, record, record.data.get("released_at"), "released_at")
        if device and version:
            firmware[device].append((record, version, released))
            if device not in devices:
                ctx.issue(record, "UNDECLARED_DEVICE", "Firmware record references an undeclared device")
    for record in groups["telemetry"]:
        device = _text(ctx, record, "device_id")
        instant = _when(ctx, record, record.observed_at or record.data.get("timestamp"), "telemetry observation time")
        if device and instant:
            if instant > ctx.as_of:
                ctx.issue(record, "FUTURE_TELEMETRY", "Telemetry timestamp lies after the analysis time")
            else:
                telemetry[device].append((instant, record))
        if device and device not in devices:
            ctx.issue(record, "UNDECLARED_DEVICE", "Telemetry references an undeclared device")
    inventory = []
    for device, record in devices.items():
        version = _text(ctx, record, "firmware_version", required=False)
        catalog_versions = {value for _, value, instant in firmware[device] if instant is None or instant <= ctx.as_of}
        if version and catalog_versions and version not in catalog_versions:
            ctx.issue(record, "FIRMWARE_NOT_IN_SUPPLIED_CATALOG", "Installed firmware is absent from the supplied firmware catalog")
        max_age = _number(ctx, record, "telemetry_max_age_seconds", required=False)
        if max_age is not None and max_age <= 0:
            ctx.issue(record, "INVALID_TELEMETRY_AGE_LIMIT", "telemetry_max_age_seconds must be positive")
            max_age = None
        max_age = 86400 if max_age is None else max_age
        latest = max(telemetry[device], default=None, key=lambda row: row[0])
        age = (ctx.as_of - latest[0]).total_seconds() if latest else None
        if latest and age > max_age:
            ctx.finding("IOT_TELEMETRY_STALE", "The latest supplied telemetry exceeds the stated record-age threshold",
                        [record.record_id, latest[1].record_id], {"device_id": device, "age_seconds": age, "threshold_seconds": max_age})
        elif latest is None:
            ctx.issue(record, "TELEMETRY_MISSING", "No telemetry at or before analysis time was supplied")
        inventory.append({"record_id": record.record_id, "device_id": device, "firmware_version": version,
                          "catalog_versions": sorted(catalog_versions), "latest_telemetry_age_seconds": age})
    return _finish(ctx, {"devices": len(devices), "firmware_records": sum(map(len, firmware.values())),
                         "telemetry_records": sum(map(len, telemetry.values()))}, {"device_inventory": inventory},
                   ("A stale or missing submitted telemetry record does not prove that a device is offline.",))


def otint(ctx: AnalysisContext):
    groups = _groups(ctx, {"zone", "asset", "conduit", "communication", "change"}, "asset")
    zones, assets, conduits, communications = {}, {}, [], []
    for record in groups["zone"]:
        zone = _text(ctx, record, "zone_id")
        if zone:
            if zone in zones:
                ctx.issue(record, "DUPLICATE_ZONE_ID", "Zone ID repeats in the supplied inventory")
            zones.setdefault(zone, record)
    for record in groups["asset"]:
        asset, zone = _text(ctx, record, "asset_id"), _text(ctx, record, "zone_id")
        if asset and zone:
            if asset in assets:
                ctx.issue(record, "DUPLICATE_ASSET_ID", "Asset ID repeats in the supplied inventory")
            assets.setdefault(asset, (record, zone))
            if zone not in zones:
                ctx.issue(record, "UNDECLARED_ZONE", "Asset zone is absent from the supplied zone inventory")
    for record in groups["conduit"]:
        left, right = _text(ctx, record, "from_zone"), _text(ctx, record, "to_zone")
        protocols = _strings(ctx, record, "allowed_protocols")
        if left and right:
            conduits.append((left, right, {protocol.lower() for protocol in protocols}, record))
            if left not in zones or right not in zones:
                ctx.issue(record, "UNDECLARED_ZONE", "Conduit endpoints are absent from the zone inventory")
    for record in groups["communication"]:
        left, right, protocol = _text(ctx, record, "from_asset"), _text(ctx, record, "to_asset"), _text(ctx, record, "protocol")
        if not left or not right or not protocol:
            continue
        if left not in assets or right not in assets:
            ctx.issue(record, "UNDECLARED_ASSET", "Communication endpoints are absent from the asset inventory")
            continue
        source_zone, target_zone = assets[left][1], assets[right][1]
        matching = [conduit for conduit in conduits if conduit[0] == source_zone and conduit[1] == target_zone and protocol.lower() in conduit[2]]
        declared = source_zone == target_zone or bool(matching)
        communications.append({"record_id": record.record_id, "from_zone": source_zone, "to_zone": target_zone,
                               "protocol": protocol, "declared_conduit_match": declared})
        if not declared:
            ctx.finding("OT_COMMUNICATION_OUTSIDE_SUPPLIED_CONDUITS", "A cross-zone communication lacks a matching supplied protocol conduit",
                        [record.record_id, assets[left][0].record_id, assets[right][0].record_id],
                        {"from_zone": source_zone, "to_zone": target_zone, "protocol": protocol})
    for record in groups["change"]:
        asset = _text(ctx, record, "asset_id")
        approved = _boolean(ctx, record, "approved")
        if approved is False:
            ctx.finding("OT_CHANGE_NOT_APPROVED_DECLARED", "A supplied OT change record explicitly lacks approval", [record.record_id], {"asset_id": asset})
        if asset not in assets:
            ctx.issue(record, "UNDECLARED_ASSET", "Change record references an undeclared asset")
    return _finish(ctx, {"zones": len(zones), "assets": len(assets), "conduits": len(conduits),
                         "communications_checked": len(communications)}, {"zone_communication_matrix": communications},
                   ("Conduit inventory completeness and actual enforcement are not established by these supplied records.",))


def icsint(ctx: AnalysisContext):
    groups = _groups(ctx, {"threshold", "process_sample", "command"}, "process_sample")
    thresholds, samples, commands = defaultdict(list), [], 0
    for record in groups["threshold"]:
        asset, tag, unit = _text(ctx, record, "asset_id"), _text(ctx, record, "tag"), _text(ctx, record, "unit")
        low, high = _number(ctx, record, "low", required=False), _number(ctx, record, "high", required=False)
        if low is None and high is None:
            ctx.issue(record, "THRESHOLD_BOUNDS_MISSING", "At least one numeric threshold bound is required")
        elif low is not None and high is not None and low > high:
            ctx.issue(record, "INVALID_THRESHOLD_INTERVAL", "The lower threshold exceeds the upper threshold")
        elif asset and tag and unit:
            thresholds[(asset, tag, unit)].append((record, low, high))
    for record in groups["process_sample"]:
        asset, tag, unit = _text(ctx, record, "asset_id"), _text(ctx, record, "tag"), _text(ctx, record, "unit")
        value = _number(ctx, record, "value")
        if not asset or not tag or not unit or value is None:
            continue
        matched = thresholds[(asset, tag, unit)]
        state = "NO_SUPPLIED_THRESHOLD"
        if len({(low, high) for _, low, high in matched}) > 1:
            state = "CONFLICTING_THRESHOLDS"
            ctx.issue(record, "THRESHOLD_CONFLICT", "Supplied thresholds disagree; sample classification remains unresolved")
        elif matched:
            baseline, low, high = matched[0]
            outside = (low is not None and value < low) or (high is not None and value > high)
            state = "OUTSIDE_SUPPLIED_THRESHOLD" if outside else "WITHIN_SUPPLIED_THRESHOLD"
            if outside:
                ctx.finding("ICS_PROCESS_THRESHOLD_EXCEEDED", "A supplied process value lies outside a supplied threshold",
                            [record.record_id, baseline.record_id], {"asset_id": asset, "tag": tag, "value": value, "unit": unit, "low": low, "high": high})
        else:
            ctx.issue(record, "THRESHOLD_MISSING_OR_UNIT_MISMATCH", "No threshold with the same asset, tag, and unit was supplied")
        quality = record.data.get("quality")
        if quality is not None and (not isinstance(quality, str) or quality not in {"GOOD", "BAD", "UNCERTAIN"}):
            ctx.issue(record, "INVALID_SAMPLE_QUALITY", "Sample quality must be GOOD, BAD, or UNCERTAIN")
        elif quality is not None and quality != "GOOD":
            ctx.finding("ICS_SAMPLE_QUALITY_FLAG", "A supplied process sample has a quality flag other than GOOD",
                        [record.record_id], {"asset_id": asset, "tag": tag, "quality": quality})
        samples.append({"record_id": record.record_id, "asset_id": asset, "tag": tag, "unit": unit, "state": state})
    for record in groups["command"]:
        command = _text(ctx, record, "command_id")
        approved = _boolean(ctx, record, "approved")
        if command:
            commands += 1
        if approved is False:
            ctx.finding("ICS_COMMAND_NOT_APPROVED_DECLARED", "A supplied industrial command record explicitly lacks approval",
                        [record.record_id], {"command_id": command})
        elif approved is None:
            ctx.issue(record, "COMMAND_APPROVAL_UNKNOWN", "Command approval was not supplied")
    return _finish(ctx, {"process_samples_checked": len(samples), "threshold_keys": len(thresholds), "command_records": commands},
                   {"sample_classifications": samples},
                   ("Thresholds are supplied comparison criteria, not validated engineering safety limits or control recommendations.",))


def _pointer(document, reference):
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return None
    current = document
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and len(token) < 10 and int(token) < len(current):
            current = current[int(token)]
        else:
            return None
    return current


def apiint(ctx: AnalysisContext):
    groups = _groups(ctx, {"openapi"}, "openapi")
    operations, references = [], Counter()
    methods = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}
    for record in groups["openapi"]:
        document = record.data.get("document")
        if not isinstance(document, dict) or not isinstance(document.get("openapi"), str) or not document["openapi"].startswith("3."):
            ctx.issue(record, "UNSUPPORTED_API_DOCUMENT", "Supply an OpenAPI 3 JSON object")
            continue
        paths = document.get("paths")
        components = document.get("components", {})
        schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
        if not isinstance(paths, dict) or not isinstance(schemes, dict):
            ctx.issue(record, "INVALID_OPENAPI_COLLECTION", "paths and securitySchemes must be objects")
            continue
        pending = [document]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                if "$ref" in value:
                    ref = value["$ref"]
                    if not isinstance(ref, str):
                        ctx.issue(record, "INVALID_REFERENCE", "OpenAPI $ref must be a string")
                    elif not ref.startswith("#/"):
                        references["external_not_fetched"] += 1
                        ctx.issue(record, "EXTERNAL_REFERENCE_UNRESOLVED", "External references were not fetched")
                    elif _pointer(document, ref) is None:
                        references["unresolved_local"] += 1
                        ctx.issue(record, "LOCAL_REFERENCE_UNRESOLVED", "A local OpenAPI reference does not resolve")
                    else:
                        references["resolved_local"] += 1
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        operation_ids, shapes = {}, {}
        for path, path_item in paths.items():
            if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
                ctx.issue(record, "INVALID_API_PATH", "OpenAPI paths require slash-prefixed strings and operation objects")
                continue
            if "$ref" in path_item:
                resolved = _pointer(document, path_item["$ref"])
                if isinstance(resolved, dict):
                    path_item = resolved
                else:
                    continue
            for method, operation in path_item.items():
                if method not in methods:
                    continue
                if not isinstance(operation, dict):
                    ctx.issue(record, "INVALID_OPERATION", "API operations must be objects")
                    continue
                operation_id = operation.get("operationId")
                if operation_id is not None:
                    if not isinstance(operation_id, str) or not operation_id:
                        ctx.issue(record, "INVALID_OPERATION_ID", "operationId must be a nonempty string")
                    elif operation_id in operation_ids:
                        ctx.finding("DUPLICATE_API_OPERATION_ID", "An OpenAPI document repeats an operationId",
                                    [record.record_id], {"operation_id": operation_id})
                    else:
                        operation_ids[operation_id] = (method, path)
                shape = method, re.sub(r"\{[^{}]+\}", "{}", path)
                if shape in shapes:
                    ctx.finding("AMBIGUOUS_API_PATH_TEMPLATE", "Two operations differ only in path-parameter names",
                                [record.record_id], {"method": method.upper(), "paths": [shapes[shape], path]})
                shapes[shape] = path
                security = operation.get("security", document.get("security", []))
                if not isinstance(security, list) or any(not isinstance(requirement, dict) for requirement in security):
                    ctx.issue(record, "INVALID_SECURITY_REQUIREMENTS", "OpenAPI security must be an array of requirement objects")
                    auth = "INVALID_DECLARATION"
                else:
                    auth = "OPTIONAL_OR_NOT_REQUIRED_BY_SPEC" if not security or any(not requirement for requirement in security) else "REQUIRED_BY_SPEC"
                    for requirement in security:
                        for scheme in requirement:
                            if scheme not in schemes:
                                ctx.issue(record, "UNDECLARED_SECURITY_SCHEME", "An operation references an undeclared security scheme")
                    if auth == "OPTIONAL_OR_NOT_REQUIRED_BY_SPEC":
                        ctx.finding("API_AUTH_NOT_REQUIRED_BY_SPEC", "A supplied operation has no mandatory security requirement in its specification",
                                    [record.record_id], {"method": method.upper(), "path": path})
                parameters = []
                for owner in (path_item, operation):
                    declared = owner.get("parameters", [])
                    if isinstance(declared, list):
                        parameters.extend(declared)
                    else:
                        ctx.issue(record, "INVALID_PARAMETERS", "Operation parameters must be an array")
                named = {}
                for parameter in parameters:
                    if isinstance(parameter, dict) and "$ref" in parameter:
                        parameter = _pointer(document, parameter["$ref"])
                    if isinstance(parameter, dict) and parameter.get("in") == "path" and isinstance(parameter.get("name"), str):
                        named[parameter["name"]] = parameter
                for name in re.findall(r"\{([^{}]+)\}", path):
                    if name not in named or named[name].get("required") is not True:
                        ctx.finding("API_PATH_PARAMETER_CONTRACT_GAP", "A path parameter lacks a matching required parameter declaration",
                                    [record.record_id], {"method": method.upper(), "path": path, "parameter": name})
                responses = operation.get("responses")
                if not isinstance(responses, dict) or not responses:
                    ctx.finding("API_RESPONSE_CONTRACT_MISSING", "An operation lacks a nonempty response contract",
                                [record.record_id], {"method": method.upper(), "path": path})
                operations.append({"record_id": record.record_id, "method": method.upper(), "path": path,
                                   "operation_id": operation_id, "security_state": auth,
                                   "response_codes": sorted(responses) if isinstance(responses, dict) else []})
    return _finish(ctx, {"operations": len(operations), "reference_counts": dict(references),
                         "operations_with_required_security": sum(item["security_state"] == "REQUIRED_BY_SPEC" for item in operations)},
                   {"operation_contracts": operations},
                   ("OpenAPI security declarations do not verify authentication or authorization enforcement on deployed services.",))


def _cwe(ctx, record, value):
    if not isinstance(value, str) or not re.fullmatch(r"CWE-[1-9]\d*", value.strip(), re.I):
        ctx.issue(record, "INVALID_CWE_ID", "CWE identifiers require the form CWE- followed by a positive integer")
        return None
    return value.strip().upper()


def cweint(ctx: AnalysisContext):
    groups = _groups(ctx, {"finding_mapping", "cwe"}, "finding_mapping")
    catalog, parent_edges, mappings, mapped_findings = {}, [], [], defaultdict(set)
    for record in groups["cwe"]:
        cwe = _cwe(ctx, record, record.data.get("cwe_id"))
        if not cwe:
            continue
        catalog[cwe] = record
        for raw_parent in _strings(ctx, record, "parents"):
            parent = _cwe(ctx, record, raw_parent)
            if parent:
                parent_edges.append((cwe, parent, record))
    for record in groups["finding_mapping"]:
        finding = _text(ctx, record, "finding_id")
        values = record.data.get("cwe_ids")
        if values is None and record.data.get("cwe_id") is not None:
            values = [record.data["cwe_id"]]
        if not isinstance(values, list):
            ctx.issue(record, "CWE_MAPPING_MISSING", "A finding requires cwe_ids or cwe_id")
            continue
        identifiers = sorted({identifier for value in values if (identifier := _cwe(ctx, record, value))})
        if finding and identifiers:
            mappings.append({"record_id": record.record_id, "finding_id": finding, "cwe_ids": identifiers, "classification_basis": "SUPPLIED_MAPPING"})
            for identifier in identifiers:
                mapped_findings[identifier].add(finding)
                if catalog and identifier not in catalog:
                    ctx.issue(record, "CWE_NOT_IN_SUPPLIED_CATALOG", "A classification is absent from the supplied CWE catalog")
        elif finding:
            ctx.issue(record, "CWE_MAPPING_EMPTY", "No valid weakness classifications were supplied for the finding")
    for left, right, record in parent_edges:
        if right not in catalog:
            ctx.issue(record, "UNRESOLVED_CWE_PARENT", "A parent CWE is absent from the supplied catalog")
    _, cycles = _graph(catalog, [(left, right) for left, right, _ in parent_edges])
    for cycle in cycles:
        ctx.finding("CWE_HIERARCHY_CYCLE", "The supplied weakness hierarchy contains a cyclic component",
                    [record.record_id for left, right, record in parent_edges if left in cycle and right in cycle],
                    {"cwe_ids": cycle})
    for identifier, finding_ids in sorted(mapped_findings.items()):
        if len(finding_ids) > 1:
            related = [mapping["record_id"] for mapping in mappings if identifier in mapping["cwe_ids"]]
            ctx.finding("RECURRING_SUPPLIED_WEAKNESS_CLASSIFICATION", "Multiple supplied findings share a weakness classification",
                        related, {"cwe_id": identifier, "distinct_findings": len(finding_ids)})
    return _finish(ctx, {"mapped_finding_records": len(mappings), "catalog_entries": len(catalog),
                         "distinct_findings_by_cwe": {key: len(value) for key, value in sorted(mapped_findings.items())}},
                   {"weakness_mappings": mappings, "cyclic_hierarchy_components": cycles},
                   ("CWE classifications and hierarchy names are supplied metadata; no MITRE catalog or exploitability verification was performed.",))


UNITS = {
    "s": ("duration_seconds", 1), "ms": ("duration_seconds", 0.001), "min": ("duration_seconds", 60),
    "Hz": ("frequency_hz", 1), "kHz": ("frequency_hz", 1000), "MHz": ("frequency_hz", 1000000), "GHz": ("frequency_hz", 1000000000),
    "B": ("storage_bytes", 1), "KB": ("storage_bytes", 1000), "KiB": ("storage_bytes", 1024),
    "MB": ("storage_bytes", 1000000), "MiB": ("storage_bytes", 1048576), "GB": ("storage_bytes", 1000000000),
    "V": ("voltage_volts", 1), "mV": ("voltage_volts", 0.001),
    "W": ("power_watts", 1), "mW": ("power_watts", 0.001), "kW": ("power_watts", 1000),
    "m": ("length_meters", 1), "cm": ("length_meters", 0.01), "mm": ("length_meters", 0.001), "km": ("length_meters", 1000),
}


def _quantity(ctx, record, value, unit):
    if unit not in UNITS:
        ctx.issue(record, "UNSUPPORTED_UNIT", "Numeric specifications require a supported, case-sensitive unit")
        return None
    dimension, scale = UNITS[unit]
    try:
        normalized = value * scale
        if not math.isfinite(normalized):
            raise OverflowError()
    except (OverflowError, TypeError):
        ctx.issue(record, "QUANTITY_OVERFLOW", "The supplied quantity cannot be represented as a finite normalized value")
        return None
    return dimension, normalized


def techint(ctx: AnalysisContext):
    groups = _groups(ctx, {"specification", "requirement"}, "specification")
    quantities, textual, requirements, artifacts = defaultdict(list), defaultdict(list), [], []
    for record in groups["specification"]:
        product, property_name = _text(ctx, record, "product_id"), _text(ctx, record, "property")
        if not product or not property_name:
            continue
        value, unit = record.data.get("value"), record.data.get("unit")
        if isinstance(value, str):
            normalized = " ".join(value.split())
            if not normalized:
                ctx.issue(record, "SPECIFICATION_VALUE_MISSING", "Specification value must not be empty")
                continue
            textual[(product, property_name)].append((record, normalized))
            artifacts.append({"record_id": record.record_id, "product_id": product, "property": property_name, "value_kind": "TEXT"})
        else:
            value = _number(ctx, record, "value")
            if value is None:
                continue
            if not isinstance(unit, str):
                ctx.issue(record, "UNIT_MISSING", "Numeric specifications require a string unit")
                continue
            normalized = _quantity(ctx, record, value, unit)
            if normalized:
                dimension, quantity = normalized
                quantities[(product, property_name, dimension)].append((record, quantity))
                artifacts.append({"record_id": record.record_id, "product_id": product, "property": property_name,
                                  "dimension": dimension, "normalized_value": quantity})
    for (product, property_name, dimension), rows in quantities.items():
        reference = rows[0][1]
        if any(not math.isclose(reference, value, rel_tol=1e-9, abs_tol=1e-12) for _, value in rows[1:]):
            ctx.finding("NUMERIC_SPECIFICATION_VARIATION", "Supplied technical specifications normalize to different values",
                        [record.record_id for record, _ in rows],
                        {"product_id": product, "property": property_name, "dimension": dimension,
                         "normalized_values": sorted({value for _, value in rows})})
    for (product, property_name), rows in textual.items():
        if len({value for _, value in rows}) > 1:
            ctx.finding("TEXT_SPECIFICATION_VARIATION", "Supplied textual technical specifications differ",
                        [record.record_id for record, _ in rows], {"product_id": product, "property": property_name})
    for record in groups["requirement"]:
        product, property_name, unit = _text(ctx, record, "product_id"), _text(ctx, record, "property"), _text(ctx, record, "unit")
        low, high = _number(ctx, record, "minimum", required=False), _number(ctx, record, "maximum", required=False)
        if not product or not property_name or not unit:
            continue
        if low is None and high is None:
            ctx.issue(record, "REQUIREMENT_BOUNDS_MISSING", "At least one numeric requirement bound must be supplied")
            continue
        lower = _quantity(ctx, record, low, unit) if low is not None else None
        upper = _quantity(ctx, record, high, unit) if high is not None else None
        if (low is not None and lower is None) or (high is not None and upper is None):
            continue
        dimension = (lower or upper)[0]
        minimum, maximum = lower[1] if lower else None, upper[1] if upper else None
        if minimum is not None and maximum is not None and minimum > maximum:
            ctx.issue(record, "INVALID_REQUIREMENT_INTERVAL", "The minimum requirement exceeds the maximum")
            continue
        matched = quantities[(product, property_name, dimension)]
        if not matched:
            ctx.issue(record, "COMPARABLE_SPECIFICATION_MISSING", "No supplied numeric specification has the required product, property and dimension")
        for specification, value in matched:
            met = not ((minimum is not None and value < minimum) or (maximum is not None and value > maximum))
            requirements.append({"specification_record_id": specification.record_id, "requirement_record_id": record.record_id,
                                 "within_supplied_requirement": met, "dimension": dimension})
            if not met:
                ctx.finding("TECHNICAL_REQUIREMENT_MISMATCH", "A supplied technical specification lies outside a supplied requirement",
                            [record.record_id, specification.record_id],
                            {"product_id": product, "property": property_name, "normalized_value": value,
                             "minimum": minimum, "maximum": maximum, "dimension": dimension})
    return _finish(ctx, {"numeric_specification_records": sum(map(len, quantities.values())),
                         "textual_specification_records": sum(map(len, textual.values())),
                         "requirement_comparisons": len(requirements), "unit_method": "DECLARED_DIMENSION_LINEAR_CONVERSION"},
                   {"normalized_specifications": artifacts, "requirement_comparisons": requirements},
                   ("Specifications may describe different revisions or times; variation is not automatically a factual contradiction.",))


HANDLERS = {
    "REPOINT": repoint, "PACKAGEINT": packageint, "SBOMINT": sbomint, "DEPENDENCYINT": dependencyint,
    "CODEINT": codeint, "DEVINT": devint, "CICDINT": cicdint, "APPINT": appint, "MOBILEINT": mobileint,
    "IOTINT": iotint, "OTINT": otint, "ICSINT": icsint, "APIINT": apiint, "CWEINT": cweint, "TECHINT": techint,
}

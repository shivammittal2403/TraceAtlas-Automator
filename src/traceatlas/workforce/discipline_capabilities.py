"""Source-backed native capabilities; catalog metadata grants no execution authority."""
from __future__ import annotations

import ast
from hashlib import sha256
import inspect
import json
from pathlib import Path

from ..osint_taxonomy import GROUP_NAMES, GROUP_TERMS, build_taxonomy
from ..addons.intelligence_v1.registry import catalog as legacy_catalog
from .discipline_engines import registered_handlers, engine_identity
from .discipline_engines.common import make_context
from .discipline_skills import get_skill_guide
from .discipline_review import REVIEWED_DISCIPLINES

SCHEMA = "traceatlas.discipline.capabilities.v1"
FAMILY_TESTS = {
    "network": "tests/test_discipline_network.py",
    "software": "tests/test_discipline_software.py",
    "discovery": "tests/test_discovery_employees.py",
    "economic": "tests/test_discipline_economic.py",
    "social": "tests/test_discipline_social.py",
    "cyber": "tests/test_cyber_employees.py",
    "media": "tests/test_media_evidence_employees.py",
    "evidence": "tests/test_media_evidence_employees.py",
    "fraud": "tests/test_discipline_fraud.py",
    "research": "tests/test_research_employees.py",
    "supply": "tests/test_supply_employees.py",
}
DYNAMIC_TEST_CLASSES = {
    "software": "SoftwareEmployeeTests", "economic": "EconomicEmployeeTests",
    "social": "SocialEmployeeTests", "fraud": "FraudEmployeeTests",
}
SHARED_TESTS = (
    "tests/test_discipline_contracts.py",
    "tests/test_discipline_all140_lifecycle.py",
    "tests/test_discipline_skills.py",
)
MAX_SOURCE_BYTES = 1024 * 1024


def domain_groups():
    """Return the ten repository-native groups; implementation families are separate."""
    if set(GROUP_NAMES) != set(GROUP_TERMS):
        raise ValueError("Native group names and terms differ")
    groups, seen = [], set()
    for group_id, terms in sorted(GROUP_TERMS.items()):
        labels = tuple(terms.split())
        if not labels or len(set(labels)) != len(labels) or seen.intersection(labels):
            raise ValueError("Native groups contain absent or duplicate disciplines")
        seen.update(labels)
        groups.append({"group_id": group_id, "group_name": GROUP_NAMES[group_id],
                       "disciplines": labels})
    return tuple(groups)


def discipline_group(label):
    """Resolve one registered taxonomy label without changing its authority."""
    if not isinstance(label, str):
        raise ValueError("Discipline must be a registered label")
    selected = label.strip().upper()
    for group in domain_groups():
        if selected in group["disciplines"]:
            return {"group_id": group["group_id"], "group_name": group["group_name"]}
    raise ValueError("Unknown native discipline")


def _read_source(path):
    raw = path.read_bytes()
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("Capability source exceeds its bounded inspection limit")
    return raw, ast.parse(raw.decode("utf-8"), filename=str(path))


def _resolve(node, bindings, active=()):
    if isinstance(node, ast.Name) and node.id in bindings and node.id not in active:
        return _resolve(bindings[node.id], bindings, active + (node.id,))
    return node


def _literal(node, bindings):
    node = _resolve(node, bindings)
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _dictionary_keys(node, bindings, depth=0):
    if depth > 16:
        return set()
    node = _resolve(node, bindings)
    if isinstance(node, ast.Dict):
        result = set()
        for key, value in zip(node.keys, node.values):
            if key is None:
                result.update(_dictionary_keys(value, bindings, depth + 1))
            else:
                literal = _literal(key, bindings)
                if literal is not None:
                    result.add(literal)
        return result
    if isinstance(node, ast.BoolOp):
        return set().union(*(_dictionary_keys(value, bindings, depth + 1) for value in node.values))
    if isinstance(node, ast.BinOp):
        return _dictionary_keys(node.left, bindings, depth + 1) | _dictionary_keys(node.right, bindings, depth + 1)
    return set()


def _static_outputs(tree, function_name):
    """Inspect literal outputs and context helpers, without evaluating handler code."""
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if function_name not in functions:
        raise ValueError("Registered native handler has no source function")
    found = {"metrics": set(), "artifacts": set(), "findings": set(), "issues": set()}

    def visit(function, bindings, active):
        if len(active) > 8:
            return
        local = dict(bindings)
        for node in ast.walk(function):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, (ast.Dict, ast.Name, ast.BoolOp, ast.BinOp)):
                    local[node.targets[0].id] = node.value
        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Subscript)
                            and _literal(target.value.slice, local) in {"metrics", "artifacts"}):
                        category = _literal(target.value.slice, local)
                        key = _literal(target.slice, local)
                        if key is not None:
                            found[category].add(key)
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "output":
                    for keyword in node.keywords:
                        if keyword.arg in {"metrics", "artifacts"}:
                            found[keyword.arg].update(_dictionary_keys(keyword.value, local))
                elif node.func.attr == "finding" and node.args:
                    key = _literal(node.args[0], local)
                    if key is not None:
                        found["findings"].add(key)
                elif node.func.attr == "issue" and len(node.args) > 1:
                    key = _literal(node.args[1], local)
                    if key is not None:
                        found["issues"].add(key)
                elif (node.func.attr == "update" and isinstance(node.func.value, ast.Name)
                      and node.func.value.id in {"metrics", "artifacts"}):
                    for argument in node.args:
                        found[node.func.value.id].update(_dictionary_keys(argument, local))
            elif isinstance(node.func, ast.Name) and node.func.id in functions and node.func.id not in active:
                helper = functions[node.func.id]
                parameters = helper.args.posonlyargs + helper.args.args
                if not parameters or parameters[0].arg not in {"ctx", "context"}:
                    continue
                child = {parameter.arg: _resolve(value, local)
                         for parameter, value in zip(parameters, node.args)}
                child.update({item.arg: _resolve(item.value, local)
                              for item in node.keywords if item.arg is not None})
                visit(helper, child, active + (node.func.id,))
    visit(functions[function_name], {}, (function_name,))
    return {key: sorted(values) for key, values in found.items()}


def _repository_root():
    candidate = Path(__file__).resolve().parents[3]
    if (candidate / "src/traceatlas/workforce/discipline_engines").is_dir():
        return candidate
    return None


def _recipe(root, label, required):
    relative = "examples/employees/recipes/" + label + ".json"
    path = root / relative if root is not None else None
    if path is None or not path.is_file():
        if required:
            raise ValueError("Native recipe is missing: " + relative)
        return {"path": relative, "available": False, "sha256": None,
                "status": "NOT_AVAILABLE_IN_INSTALLATION", "synthetic": True}
    raw = path.read_bytes()
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("Native recipe exceeds bounded inspection limit")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("discipline") != label or not value.get("records"):
        raise ValueError("Native recipe identity or nonempty records are missing")
    make_context(value)
    return {"path": relative, "available": True, "sha256": sha256(raw).hexdigest(),
            "status": "SHARED_INPUT_CONTRACT_VALIDATED_FIXTURE", "synthetic": True}



def _test_selector(node, label, category):
    """Resolve only the literal unittest name construction used by bundled tests."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return {"label": label, "_label": label, "category": category}.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _test_selector(node.left, label, category)
        right = _test_selector(node.right, label, category)
        return left + right if left is not None and right is not None else None
    if (isinstance(node, ast.Call) and not node.args and not node.keywords
            and isinstance(node.func, ast.Attribute) and node.func.attr == "lower"):
        value = _test_selector(node.func.value, label, category)
        return value.lower() if value is not None else None
    return None

def _test_references(root, family, label):
    relative = FAMILY_TESTS[family]
    path = root / relative if root is not None else None
    selectors, cases = [], []
    available = bool(path is not None and path.is_file())
    if available:
        _, tree = _read_source(path)
        for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            for method in (node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")):
                if any(isinstance(node, ast.Constant) and node.value == label for node in ast.walk(method)):
                    selectors.append(cls.name + "." + method.name)
        dynamic_class = DYNAMIC_TEST_CLASSES.get(family)
        class_names = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
        dynamic_calls = [node for node in ast.walk(tree)
                         if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                         and node.func.id == "setattr" and len(node.args) >= 2
                         and isinstance(node.args[0], ast.Name)
                         and node.args[0].id == dynamic_class]
        if dynamic_class in class_names and dynamic_calls:
            for node in tree.body:
                if (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "CASES" for target in node.targets)
                        and isinstance(node.value, ast.Call) and node.value.args
                        and isinstance(node.value.args[0], ast.Constant) and isinstance(node.value.args[0].value, str)):
                    supplied = json.loads(node.value.args[0].value)
                    for category in ("positive", "adversarial"):
                        if label in supplied.get(category, {}):
                            cases.append("CASES." + category + "." + label)
                            suffix = ("semantics" if category == "positive" else "malformed") if family == "economic" else category
                            for call in dynamic_calls:
                                name = _test_selector(call.args[1], label, category)
                                if name == "test_" + label.lower() + "_" + suffix:
                                    selectors.append(dynamic_class + "." + name)
    return {"path": relative, "source_available": available, "selectors": sorted(set(selectors)),
            "structured_case_references": cases,
            "definition_status": "SOURCE_REFERENCED" if selectors else "NOT_ESTABLISHED",
            "execution_receipt": None}


def capability_catalog(*, repository_root=None, require_repository_assets=False):
    """Report implemented native contracts separately from legacy routes and live sources."""
    groups = domain_groups()
    expected = {label for group in groups for label in group["disciplines"]}
    handlers = registered_handlers()
    if set(handlers) != expected:
        raise ValueError("Native capability mapping requires every taxonomy handler exactly once")
    legacy = legacy_catalog()
    routes = build_taxonomy(legacy)
    if set(routes) != expected:
        raise ValueError("Legacy routes do not match the native taxonomy")
    root = Path(repository_root).resolve() if repository_root is not None else _repository_root()
    source_cache, rows = {}, []
    for label, handler in sorted(handlers.items()):
        original = inspect.unwrap(handler)
        module, function = original.__module__, original.__name__
        family = module.rsplit(".", 1)[-1]
        if family not in FAMILY_TESTS or not callable(handler):
            raise ValueError("Native handler has an unknown implementation family")
        source_path = inspect.getsourcefile(original)
        if source_path is None:
            raise ValueError("Native handler source is unavailable")
        path = Path(source_path)
        if path not in source_cache:
            raw, tree = _read_source(path)
            source_cache[path] = (raw, tree)
        raw, tree = source_cache[path]
        function_nodes = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        if function not in function_nodes:
            raise ValueError("Native handler function is absent from its source")
        guide = get_skill_guide(label)
        static = _static_outputs(tree, function)
        review_mode = ("SUPPLIED_COMPETING_HYPOTHESES" if label == "HYPOTHESISINT" else
                       "SUPPLIED_FALSIFICATION_PROTOCOL" if label == "FALSIFICATIONINT" else "NO_SPECIALIZED_PROJECTION")
        rows.append({
            "discipline": label, "classification": "umbrella" if label == "OSINT" else "discipline",
            **discipline_group(label),
            "native_handler": {"module": module, "function": function, "implementation_family": family,
                               "registry_dispatch": "registered_handlers()[discipline]",
                               "registered_wrapper": handler is not original,
                               "source_path": "src/traceatlas/workforce/discipline_engines/" + family + ".py",
                               "source_line": function_nodes[function].lineno,
                               "source_sha256": sha256(raw).hexdigest(), "engine_sha256": engine_identity(label)},
            "analysis_method": inspect.getdoc(original),
            "analysis_method_status": "SOURCE_DOCSTRING" if inspect.getdoc(original) else "NO_SOURCE_DOCSTRING",
            "static_output_contract": {**static, "exhaustive": False,
                                       "basis": "TRUSTED_SOURCE_AST_LITERAL_KEYS_ONLY",
                                       "code_executed_for_extraction": False},
            "native_execution": {"implementation_status": "CALLABLE_REGISTERED",
                                 "mode": "SUPPLIED_RECORD_ANALYSIS", "network_calls": 0, "model_calls": 0,
                                 "execution_receipt": None},
            "native_recipe": _recipe(root, label, require_repository_assets),
            "skill": {"path": "src/traceatlas/skills/procedures/" + label.lower() + "/SKILL.md",
                      "sha256": guide["sha256"], "metadata_validated": True,
                      "grants_source_authority": False},
            "semantic_tests": _test_references(root, family, label),
            "shared_test_references": list(SHARED_TESTS),
            "legacy_route": routes[label],
            "evidence_support": {"supplied_record_and_source_citations": True,
                                 "canonical_input_artifact_when_approved": True,
                                 "source_ids_are_assertions": True,
                                 "source_authenticity_verified": False,
                                 "factual_entailment_verified": False},
            "hypothesis_review": {"mode": review_mode, "canonical_sidecar_coded": label in REVIEWED_DISCIPLINES,
                                  "typed_hypothesis_projection_coded": label == "HYPOTHESISINT",
                                  "standalone_falsification_invents_proposition": False,
                                  "execution_receipt": None},
            "live_collection": {"status": "NOT_IMPLEMENTED_BY_NATIVE_HANDLER", "live_verified": False,
                                "related_source_fabric": "SEPARATE_APPROVED_SOURCE_CAPABILITIES",
                                "automatically_dispatched": False},
            "external_requirements": {"specification_status": "UNREAD", "minimum_requirements_met": None},
        })
    module_modes, route_modes = {}, {}
    for item in legacy["modules"]:
        module_modes[item["mode"]] = module_modes.get(item["mode"], 0) + 1
    for item in routes.values():
        route_modes[item["execution_mode"]] = route_modes.get(item["execution_mode"], 0) + 1
    return {"schema": SCHEMA, "catalog_authority": "REPOSITORY_NATIVE_REGISTRY",
            "discipline_count": sum(row["classification"] == "discipline" for row in rows),
            "umbrella_count": sum(row["classification"] == "umbrella" for row in rows),
            "registered_handler_count": len(rows), "domain_groups": groups,
            "legacy_module_count": len(legacy["modules"]), "legacy_module_modes": module_modes,
            "legacy_label_route_modes": route_modes,
            "external_specification_status": "UNREAD", "minimum_requirements_met": None,
            "execution_receipt": None, "live_verified": False,
            "limitations": ["Static output names are nonexhaustive possible outputs, not execution results.",
                            "Recipe and test definitions do not prove semantic acceptance or provider qualification.",
                            "Implementation families do not replace the ten native domain groups.",
                            "External supplied master prompt and catalog have not been compared."],
            "employees": rows}

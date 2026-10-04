"""Data-driven initial employee registry and deterministic eligibility rules."""
from __future__ import annotations

from .contracts import Budget, EmployeeDefinition, SCHEMA_VERSION, TaskEnvelope


def _employee(employee_id: str, name: str, role: str, domain: str, objective: str,
              tools: tuple[str, ...], sources: tuple[str, ...], actions: tuple[str, ...],
              capabilities: tuple[str, ...], *, version: str = "1.0.0") -> EmployeeDefinition:
    return EmployeeDefinition(
        schema_version=SCHEMA_VERSION, employee_id=employee_id, name=name, version=version,
        role=role, domain=domain, objective=objective, allowed_tools=tools,
        allowed_sources=sources, allowed_actions=actions,
        prohibited_actions=("change_scope", "grant_authority", "contact_subject", "execute_code", "install_tool"),
        required_capabilities=capabilities,
        budget_limit=Budget("USD", 1.0, 120, 8, 2),
        escalation_policy=("identity_attribution", "scope_change", "material_dispute", "report_release"),
        model_policy=("structured_output", "minimum_context", "no_training_on_case_data"),
    )


INITIAL_EMPLOYEES: tuple[EmployeeDefinition, ...] = (
    _employee("case-manager", "Case Manager", "manager", "CASEWORK",
              "Maintain bounded case progress and route approved work",
              ("investigation.plan",), (), ("propose_plan", "route_task"), ("case_management",)),
    _employee("investigation-planner", "Investigation Planner", "planner", "PLANNING",
              "Propose typed, bounded investigation plans for deterministic validation",
              ("investigation.plan", "search.query"), (), ("propose_plan", "estimate_information_gain"), ("planning",)),
    _employee("webint-infra-specialist", "WEBINT/INFRAINT Specialist", "specialist", "WEBINT_INFRAINT",
              "Collect and interpret approved public domain and infrastructure evidence",
              ("search.execute", "dns.lookup", "rdap.lookup", "archive.lookup", "ip.lookup", "registry.lookup", "vulnerability.lookup", "package.lookup", "evidence.retrieve"),
              ("dns", "rdap", "rdap_bootstrap", "wayback", "urlscan", "internetdb", "ipwhois", "ipdata", "greynoise",
               "brave", "searxng", "cloudflare_dns", "crtsh", "ripestat", "gleif", "companieshouse", "sec",
               "opencorporates", "github", "shodan", "virustotal", "nvd", "epss", "osv", "npm", "approved_search", "approved_export"),
              ("request_collection", "propose_observation", "propose_claim"),
              ("webint", "infraint", "vulnint", "domain", "ip", "person", "company", "cve", "vulnerability", "package"), version="1.4.0"),
    _employee("verification-supervisor", "Verification Supervisor", "supervisor", "VERIFICATION",
              "Challenge material claims and surface contradictions without changing evidence",
              ("evidence.verify", "verification.run", "graph.query"), (),
              ("propose_critique", "propose_verification_status"), ("verification", "source_independence")),
    _employee("report-analyst", "Report Analyst", "analyst", "REPORTING",
              "Draft evidence-linked reports for human release review",
              ("evidence.retrieve", "graph.query", "report.generate"), (),
              ("draft_report",), ("reporting",)),
)


class EmployeeRegistry:
    def __init__(self, definitions: tuple[EmployeeDefinition, ...] = INITIAL_EMPLOYEES):
        self._definitions = {item.employee_id: item for item in definitions}
        if len(self._definitions) != len(definitions):
            raise ValueError("employee IDs must be unique")

    def list(self) -> tuple[EmployeeDefinition, ...]:
        return tuple(self._definitions[key] for key in sorted(self._definitions))

    def get(self, employee_id: str) -> EmployeeDefinition:
        try:
            return self._definitions[employee_id]
        except KeyError as exc:
            raise ValueError("unknown employee") from exc

    def eligible(self, task: TaskEnvelope, allowed_tools: set[str], allowed_actions: set[str]) -> tuple[EmployeeDefinition, ...]:
        required = set(task.required_capabilities)
        rows = []
        for definition in self._definitions.values():
            if not required.intersection(definition.required_capabilities):
                continue
            if not set(definition.allowed_tools).intersection(allowed_tools):
                continue
            if not set(definition.allowed_actions).intersection(allowed_actions):
                continue
            if task.budget.tool_calls > definition.budget_limit.tool_calls or task.budget.runtime_seconds > definition.budget_limit.runtime_seconds:
                continue
            rows.append(definition)
        return tuple(sorted(rows, key=lambda item: item.employee_id))

    def select(self, task: TaskEnvelope, allowed_tools: set[str], allowed_actions: set[str]) -> EmployeeDefinition:
        candidates = self.eligible(task, allowed_tools, allowed_actions)
        if not candidates:
            raise ValueError("no eligible employee for the requested capabilities and authority")
        exact = [item for item in candidates if set(task.required_capabilities).issubset(item.required_capabilities)]
        if not exact:
            raise ValueError("no employee implements every requested capability")
        return exact[0]

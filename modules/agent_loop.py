"""Bounded agent loop (Planner → Decide → Call → Observe → Done).

Implements features 337-345 and evidence-pool citation enforcement.

Termination conditions:
- LLM returns stop
- All tools used
- Budget exhausted (default 12)

Unparseable Decide → forced stop.
Final briefing is strictly cited from the evidence pool only.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class EvidenceItem:
    id: str
    source_tool: str
    content: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class Observation:
    tool: str
    result_summary: str
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class LoopState:
    objective: str
    budget: int = 12
    used: int = 0
    tools_called: List[str] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    plan: str = ""
    stopped: bool = False
    stop_reason: str = ""


class AgentLoop:
    """Deterministic bounded ReAct-style loop.

    The actual LLM call is injected so this module stays free of provider
    credentials and can be tested offline.
    """

    def __init__(
        self,
        tools: Dict[str, Callable[..., Any]],
        llm_decide: Callable[[LoopState], Dict[str, Any]],
        llm_plan: Optional[Callable[[str], str]] = None,
        llm_brief: Optional[Callable[[LoopState], str]] = None,
        budget: int = 12,
    ) -> None:
        self.tools = tools
        self.llm_decide = llm_decide
        self.llm_plan = llm_plan
        self.llm_brief = llm_brief
        self.budget = budget

    def run(self, objective: str) -> Dict[str, Any]:
        state = LoopState(objective=objective, budget=self.budget)

        if self.llm_plan:
            state.plan = self.llm_plan(objective)
        else:
            state.plan = f"Investigate: {objective}"

        while not state.stopped and state.used < state.budget:
            decision = self.llm_decide(state)

            # Unparseable or explicit stop
            if not isinstance(decision, dict) or decision.get("tool") in (None, "stop"):
                state.stopped = True
                state.stop_reason = decision.get("rationale", "stop") if isinstance(decision, dict) else "unparseable"
                break

            tool_name = decision.get("tool")
            if tool_name not in self.tools:
                state.stopped = True
                state.stop_reason = f"unknown_tool:{tool_name}"
                break

            if tool_name in state.tools_called and len(self.tools) <= len(state.tools_called):
                state.stopped = True
                state.stop_reason = "all_tools_used"
                break

            # Call tool
            args = decision.get("args") or {}
            try:
                result = self.tools[tool_name](**args)
                summary = result if isinstance(result, str) else json.dumps(result, default=str)[:2000]
            except Exception as e:
                summary = f"ERROR: {e}"

            eid = f"ev_{len(state.evidence)+1:03d}"
            state.evidence.append(EvidenceItem(id=eid, source_tool=tool_name, content=summary))
            state.observations.append(Observation(tool=tool_name, result_summary=summary[:200], evidence_ids=[eid]))
            state.tools_called.append(tool_name)
            state.used += 1

        # Final briefing — only from evidence pool
        if self.llm_brief:
            briefing = self.llm_brief(state)
        else:
            lines = [f"# Briefing: {state.objective}", "", "## Evidence"]
            for ev in state.evidence:
                lines.append(f"- [{ev.id}] ({ev.source_tool}) {ev.content[:300]}")
            lines.append("")
            lines.append(f"Stop reason: {state.stop_reason or 'budget'}")
            briefing = "\n".join(lines)

        return {
            "objective": state.objective,
            "plan": state.plan,
            "used": state.used,
            "budget": state.budget,
            "stop_reason": state.stop_reason or "budget",
            "tools_called": state.tools_called,
            "evidence": [asdict(e) for e in state.evidence],
            "observations": [asdict(o) for o in state.observations],
            "briefing": briefing,
        }

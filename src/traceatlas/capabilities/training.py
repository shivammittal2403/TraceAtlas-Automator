from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..policy import PolicyError


QUESTION_TYPES = {"mcq", "fill-blank", "matching", "ordering", "hotspot", "scenario", "code", "short-answer"}


class TrainingStore:
    """Local JSON training-module validator and progress ledger."""

    def __init__(self, workspace: Path):
        self.path = workspace / "training-progress.json"

    @staticmethod
    def validate_module(path: Path) -> dict[str, Any]:
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            raise PolicyError("Training module must be a JSON file up to 2 MiB")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PolicyError(f"Invalid training JSON: {exc}") from exc
        if not isinstance(data, dict) or not all(str(data.get(key, "")).strip() for key in ("id", "title", "level")):
            raise PolicyError("Training module requires id, title and level")
        lessons = data.get("lessons")
        if not isinstance(lessons, list) or not lessons or len(lessons) > 100:
            raise PolicyError("Training module requires 1-100 lessons")
        exercises = 0
        for lesson in lessons:
            if not isinstance(lesson, dict) or not str(lesson.get("title", "")).strip():
                raise PolicyError("Every lesson requires a title")
            for exercise in lesson.get("exercises", []):
                if exercise.get("type") not in QUESTION_TYPES:
                    raise PolicyError(f"Unsupported exercise type: {exercise.get('type')}")
                exercises += 1
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"valid": True, "module_id": str(data["id"]), "title": str(data["title"]),
                "lessons": len(lessons), "exercises": exercises, "sha256": digest}

    def record(self, module_id: str, lesson_id: str, score: int) -> dict[str, Any]:
        if not module_id or not lesson_id:
            raise PolicyError("Module and lesson IDs are required")
        score = max(0, min(100, score))
        data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        data.setdefault(module_id, {})[lesson_id] = {"score": score, "completed": score >= 70}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return {"module_id": module_id, "lesson_id": lesson_id, **data[module_id][lesson_id]}

    def progress(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

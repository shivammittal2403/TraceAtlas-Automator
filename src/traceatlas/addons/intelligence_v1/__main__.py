"""Explicit optional GUI launcher and module catalog."""
import argparse
import importlib
import json

from .registry import catalog, contract


def main():
    parser = argparse.ArgumentParser(description="TraceAtlas supplied intelligence suite")
    parser.add_argument("command", choices=("catalog", "gui"))
    parser.add_argument("module", nargs="?")
    args = parser.parse_args()
    if args.command == "catalog":
        print(json.dumps(catalog(), indent=2))
        return
    item = contract(args.module)
    if not item.get("gui_entry"):
        parser.error("This module has no Tk panel; use the canonical archive intelligence action")
    module = importlib.import_module("traceatlas.addons.intelligence_v1.modules." + item["id"])
    app = getattr(module, item["gui_entry"])()
    app.mainloop()


if __name__ == "__main__":
    main()

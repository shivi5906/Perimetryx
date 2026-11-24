"""Command-line interface for Perimetryx's authorized reconnaissance workflow."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import yaml

from .guidance import priority_plan, research_roadmap
from .main import execute_scan, overview, scan_or_404
from .schemas import ScopeConfig
from .store import db, dump, init, load, now


def print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def read_scope(path: str) -> ScopeConfig:
    content = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return ScopeConfig(**content.get("scope", content))


def create_scope(args: argparse.Namespace) -> int:
    domain = args.domain.lower().rstrip(".")
    scope = {
        "scope": {
            "domain": domain,
            "authorization_basis": args.authorization,
            "allowed_domains": [domain],
            "excluded": [],
            "active_verification": False,
            "max_requests_per_second": 1,
            "max_concurrent_connections": 1,
            "allowed_ports": [80, 443],
            "user_agent": "Perimetryx/2.0 (+authorized assessment; contact required)",
        }
    }
    destination = Path(args.output)
    if destination.exists() and not args.force:
        print(f"Refusing to overwrite {destination}. Use --force if intentional.", file=sys.stderr)
        return 2
    destination.write_text(yaml.safe_dump(scope, sort_keys=False), encoding="utf-8")
    print(f"Created {destination}. Add a wildcard only when the program explicitly authorizes it.")
    return 0


def find_or_create_domain(scope: ScopeConfig) -> int:
    with db() as conn:
        row = conn.execute("SELECT id FROM domains WHERE root_domain = ?", (scope.domain,)).fetchone()
        if row:
            return row["id"]
        return conn.execute(
            "INSERT INTO domains(root_domain, scope_json, created_at) VALUES (?, ?, ?)",
            (scope.domain, dump(scope.model_dump()), now()),
        ).lastrowid


def run_scan(args: argparse.Namespace) -> int:
    scope = read_scope(args.scope)
    if not args.dry_run and not args.confirm_authorization:
        print("Live scans require --confirm-authorization.", file=sys.stderr)
        return 2
    domain_id = find_or_create_domain(scope)
    with db() as conn:
        scan_id = conn.execute(
            "INSERT INTO scans(domain_id, status, dry_run, started_at) VALUES (?, 'queued', ?, ?)",
            (domain_id, args.dry_run, now()),
        ).lastrowid
    asyncio.run(execute_scan(scan_id))
    scan = scan_or_404(scan_id)
    stats = load(scan["stats_json"])
    print_json({"scan_id": scan_id, "status": scan["status"], "stats": stats})
    return 0 if scan["status"] == "completed" else 1


def scan_data(scan_id: int) -> dict:
    init()
    result = overview(scan_id)
    result["scan"]["stats"] = load(result["scan"].pop("stats_json"))
    return result


def show_status(args: argparse.Namespace) -> int:
    data = scan_data(args.scan)
    print_json(data["scan"])
    return 0


def show_priorities(args: argparse.Namespace) -> int:
    data = scan_data(args.scan)
    print_json(priority_plan(data["assets"], data["findings"]))
    return 0


def show_roadmap(args: argparse.Namespace) -> int:
    data = scan_data(args.scan)
    plan = priority_plan(data["assets"], data["findings"])
    print_json({"priorities": plan, "roadmap": research_roadmap(plan)})
    return 0


def export_markdown(args: argparse.Namespace) -> int:
    data = scan_data(args.scan)
    plan = priority_plan(data["assets"], data["findings"])
    lines = [f"# Perimetryx scan {args.scan}", "", "## Priority review"]
    for item in plan:
        lines.extend(
            [
                f"### {item['hostname']} - {item['priority']}",
                item["finding"],
                "",
                f"Objective: {item['objective']}",
                *[f"- {check}" for check in item["safe_checks"]],
                "",
            ]
        )
    Path(args.output).write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="perimetryx", description="Authorized attack-surface intelligence")
    commands = root.add_subparsers(dest="command", required=True)

    init_scope = commands.add_parser("init-scope", help="Create a reviewable scope YAML file")
    init_scope.add_argument("--domain", required=True)
    init_scope.add_argument(
        "--authorization", choices=["owned_asset", "bug_bounty_program", "signed_engagement_letter"], required=True
    )
    init_scope.add_argument("--output", default="scope.yaml")
    init_scope.add_argument("--force", action="store_true")
    init_scope.set_defaults(handler=create_scope)

    scan = commands.add_parser("scan", help="Run an authorized scan from a scope YAML file")
    scan.add_argument("--scope", required=True)
    scan.add_argument("--dry-run", action="store_true")
    scan.add_argument("--confirm-authorization", action="store_true")
    scan.set_defaults(handler=run_scan)

    for name, handler, help_text in [
        ("status", show_status, "Show scan status and statistics"),
        ("prioritize", show_priorities, "Print evidence-backed manual review priorities"),
        ("roadmap", show_roadmap, "Print the responsible research roadmap for a scan"),
    ]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--scan", type=int, required=True)
        command.set_defaults(handler=handler)

    export = commands.add_parser("export", help="Export review priorities as Markdown")
    export.add_argument("--scan", type=int, required=True)
    export.add_argument("--output", default="perimetryx-report.md")
    export.set_defaults(handler=export_markdown)
    return root


def main() -> int:
    init()
    args = parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())

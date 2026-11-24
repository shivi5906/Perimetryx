"""Command-line interface for Perimetryx's Attack Surface Intelligence Platform."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

from .ai import provider
from .diff import calculate_scan_diff
from .graph import build_attack_surface_graph
from .guidance import priority_plan, research_roadmap
from .main import execute_scan, overview, scan_or_404
from .reporting import generate_html_report, generate_markdown_report
from .schemas import ScopeConfig
from .store import db, dump, init, load, now, rows

console = Console()
err_console = Console(stderr=True)

BANNER = r"""[bold cyan]
██████╗ ███████╗██████╗ ██╗███╗   ███╗███████╗████████╗██████╗ ██╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔══██╗██║████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
██████╔╝█████╗  ██████╔╝██║██╔████╔██║█████╗     ██║   ██████╔╝ ╚████╔╝  ╚███╔╝ 
██╔═══╝ ██╔══╝  ██╔══██╗██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗  ╚██╔╝   ██╔██╗ 
██║     ███████╗██║  ██║██║██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██╔╝ ██╗
[/bold cyan][dim]Attack Surface Intelligence & Evidence-Grounded Threat Engine v2.0[/dim]
"""


def severity_badge(severity: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return "[bold white on red] CRITICAL [/bold white on red]"
    elif sev == "high":
        return "[bold white on dark_orange] HIGH [/bold white on dark_orange]"
    elif sev == "medium":
        return "[bold black on yellow] MEDIUM [/bold black on yellow]"
    elif sev == "low":
        return "[bold white on blue] LOW [/bold white on blue]"
    return "[dim] INFO [/dim]"


def band_badge(band: str) -> str:
    b = (band or "low").lower()
    if b == "critical":
        return "[bold red]CRITICAL[/bold red]"
    elif b == "high":
        return "[bold dark_orange]HIGH[/bold dark_orange]"
    elif b == "medium":
        return "[bold yellow]MEDIUM[/bold yellow]"
    return "[bold green]LOW[/bold green]"


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
            "max_requests_per_second": 2,
            "max_concurrent_connections": 5,
            "allowed_ports": [80, 443],
            "user_agent": "Perimetryx/2.0 (+https://authorized-recon.local; security-audit)",
        }
    }
    destination = Path(args.output)
    if destination.exists() and not args.force:
        err_console.print(f"[bold red]Refusing to overwrite {destination}. Use --force if intentional.[/bold red]")
        return 2
    destination.write_text(yaml.safe_dump(scope, sort_keys=False), encoding="utf-8")
    console.print(f"[bold green]✔ Successfully initialized {destination}[/bold green]")
    console.print("[dim]Review and edit allowed_domains before launching live reconnaissance sweeps.[/dim]")
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


def clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    if d.startswith("https://"):
        d = d[8:]
    if d.startswith("http://"):
        d = d[7:]
    return d.split("/")[0].rstrip(".")


def run_scan(args: argparse.Namespace) -> int:
    console.print(BANNER)

    target = getattr(args, "target_domain", None) or getattr(args, "domain", None)
    if target:
        domain = clean_domain(target)
        scope = ScopeConfig(
            domain=domain,
            authorization_basis="owned_asset",
            allowed_domains=[domain, f"*.{domain}"],
            excluded=[],
            active_verification=False,
            max_requests_per_second=2.0,
            max_concurrent_connections=5,
            allowed_ports=[80, 443],
            user_agent="Perimetryx/2.0 (+https://authorized-assessment.local; security-audit)",
        )
        is_live = not getattr(args, "dry_run", False)
    elif getattr(args, "scope", None):
        try:
            scope = read_scope(args.scope)
        except Exception as e:
            err_console.print(f"[bold red]Failed to load scope configuration: {e}[/bold red]")
            return 2

        if not args.dry_run and not args.confirm_authorization:
            err_console.print("[bold red]Live reconnaissance requires explicit authorization confirmation.[/bold red]")
            console.print("Re-run with [bold yellow]--confirm-authorization[/bold yellow] or add [bold cyan]--dry-run[/bold cyan] for simulation.")
            return 2
        is_live = not args.dry_run
    else:
        err_console.print("[bold red]Error: Provide a target domain (e.g. 'perimetryx scan example.com') or '--scope scope.yaml'.[/bold red]")
        return 2

    domain_id = find_or_create_domain(scope)
    with db() as conn:
        scan_id = conn.execute(
            "INSERT INTO scans(domain_id, status, dry_run, started_at) VALUES (?, 'queued', ?, ?)",
            (domain_id, not is_live, now()),
        ).lastrowid

    console.print(Panel(
        f"[bold]Target Domain:[/bold] {scope.domain}\n"
        f"[bold]Authorization Basis:[/bold] {scope.authorization_basis}\n"
        f"[bold]Scan Mode:[/bold] {'[yellow]Dry Run (Preview Only)[/yellow]' if not is_live else '[bold green]Authorized Live Assessment[/bold green]'}\n"
        f"[bold]Scan ID:[/bold] #{scan_id}",
        title="[bold cyan]Perimetryx Execution Initialized[/bold cyan]",
        border_style="cyan"
    ))

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        disable=not sys.stdout.isatty(),
    ) as progress:
        task = progress.add_task(description=f"[cyan]Scanning {scope.domain} (passive CT, DNS, TLS, Tech, Security Rules)...[/cyan]", total=None)
        asyncio.run(execute_scan(scan_id))
        if not progress.disable:
            progress.update(task, completed=True)

    scan = scan_or_404(scan_id)
    stats = load(scan["stats_json"])

    if scan["status"] != "completed":
        console.print(f"[bold red]Scan failed:[/bold red] {stats.get('error', 'Unknown error')}")
        return 1

    console.print(f"\n[bold green]✔ Reconnaissance complete for {scope.domain} (Scan #{scan_id})[/bold green]\n")

    # Render Asset Summary Table
    with db() as conn:
        assets = rows(conn.execute(
            """SELECT a.hostname, a.environment, o.status_code, o.cname, r.total, r.band,
                      (SELECT COUNT(*) FROM findings f WHERE f.scan_id = sa.scan_id AND f.asset_id = a.id) as findings_count
               FROM scan_assets sa
               JOIN assets a ON a.id = sa.asset_id
               LEFT JOIN observations o ON o.asset_id = a.id AND o.scan_id = sa.scan_id
               LEFT JOIN risk_scores r ON r.asset_id = a.id AND r.scan_id = sa.scan_id
               WHERE sa.scan_id = ?
               ORDER BY r.total DESC""",
            (scan_id,),
        ))

    table = Table(title=f"Attack Surface Inventory: {scope.domain}", border_style="cyan")
    table.add_column("Hostname", style="bold cyan")
    table.add_column("Environment", style="dim")
    table.add_column("HTTP Status", justify="center")
    table.add_column("Risk Score", justify="right")
    table.add_column("Severity Band", justify="center")
    table.add_column("Findings", justify="right")

    for a in assets:
        table.add_row(
            a["hostname"],
            a["environment"],
            str(a["status_code"] or "Unreachable"),
            f"{a['total'] or 0}/100",
            band_badge(a["band"]),
            str(a["findings_count"]),
        )

    console.print(table)

    # Top Critical/High Findings Callout
    with db() as conn:
        top_findings = rows(conn.execute(
            """SELECT f.rule_id, f.severity, f.description, a.hostname
               FROM findings f JOIN assets a ON a.id = f.asset_id
               WHERE f.scan_id = ? AND f.severity IN ('critical', 'high')
               ORDER BY f.cvss_score DESC LIMIT 5""",
            (scan_id,),
        ))
    if top_findings:
        console.print("\n[bold red]🚨 Critical & High Security Risks Flagged:[/bold red]")
        for f in top_findings:
            console.print(f"  • {severity_badge(f['severity'])} [bold]{f['hostname']}:[/bold] {f['description']} [dim]({f['rule_id']})[/dim]")

    # Auto-generate HTML Report
    report_filename = f"perimetryx-{scope.domain}-report.html"
    try:
        html_content = generate_html_report(scan_id)
        Path(report_filename).write_text(html_content, encoding="utf-8")
        console.print(f"\n[bold green]✔ Auto-generated HTML audit report: {report_filename}[/bold green]")
    except Exception:
        pass

    console.print(f"\n[bold cyan]💡 AI Security Analyst Ready:[/bold cyan] Ask questions about this scan with:")
    console.print(f"   [yellow]uv run python -m app copilot --scan {scan_id} --query \"What are the primary attack vectors?\"[/yellow]\n")
    return 0


def run_quick_scan(args: argparse.Namespace) -> int:
    setattr(args, "target_domain", args.domain)
    return run_scan(args)


def scan_data(scan_id: int) -> dict:
    init()
    result = overview(scan_id)
    result["scan"]["stats"] = load(result["scan"].pop("stats_json"))
    return result


def show_inspect(args: argparse.Namespace) -> int:
    init()
    with db() as conn:
        scan_row = conn.execute("SELECT s.*, d.root_domain FROM scans s JOIN domains d ON d.id=s.domain_id WHERE s.id = ?", (args.scan,)).fetchone()
        if not scan_row:
            err_console.print(f"[bold red]Scan {args.scan} not found[/bold red]")
            return 1

        query = """SELECT a.id, a.hostname, a.environment, a.source,
                          o.status_code, o.title, o.cname, o.headers_json, o.response_time_ms,
                          r.total, r.band
                   FROM scan_assets sa
                   JOIN assets a ON a.id = sa.asset_id
                   LEFT JOIN observations o ON o.asset_id = a.id AND o.scan_id = sa.scan_id
                   LEFT JOIN risk_scores r ON r.asset_id = a.id AND r.scan_id = sa.scan_id
                   WHERE sa.scan_id = ?"""
        params: list[Any] = [args.scan]
        if args.host:
            query += " AND a.hostname = ?"
            params.append(args.host.lower())

        assets = rows(conn.execute(query, params))

    for a in assets:
        console.print(Panel(
            f"[bold cyan]Host:[/bold cyan] {a['hostname']} | [bold]Environment:[/bold] {a['environment']} | [bold]Risk Score:[/bold] {a['total'] or 0} ({band_badge(a['band'])})\n"
            f"[bold]HTTP Status:[/bold] {a['status_code'] or 'N/A'} | [bold]Response Time:[/bold] {a['response_time_ms']}ms\n"
            f"[bold]Page Title:[/bold] {a['title'] or 'N/A'}\n"
            f"[bold]CNAME Alias:[/bold] {a['cname'] or 'None'}",
            title=f"Asset: {a['hostname']}",
            border_style="cyan"
        ))

        # Show Findings
        with db() as conn:
            findings = rows(conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND asset_id = ?",
                (args.scan, a["id"]),
            ))
            techs = rows(conn.execute(
                "SELECT * FROM technologies WHERE scan_id = ? AND asset_id = ?",
                (args.scan, a["id"]),
            ))

        if techs:
            tech_str = ", ".join(f"[bold]{t['name']}[/bold] ({t['category']})" for t in techs)
            console.print(f"  [bold]Technologies:[/bold] {tech_str}")

        if findings:
            console.print("  [bold]Security Findings:[/bold]")
            for f in findings:
                console.print(f"    • {severity_badge(f['severity'])} [bold]{f['rule_id']}:[/bold] {f['description']}")
                if f.get("mitre_technique"):
                    console.print(f"      [dim]MITRE: {f['mitre_technique']} | CWE: {f['cwe_id']} | CVSS: {f['cvss_score']}[/dim]")
        else:
            console.print("  [dim green]✔ No security anomalies detected on this asset.[/dim green]")
        console.print("")

    return 0


def show_graph(args: argparse.Namespace) -> int:
    init()
    graph_data = build_attack_surface_graph(args.scan)
    if args.json:
        print(json.dumps(graph_data, indent=2))
        return 0

    tree = Tree(f"[bold cyan]Attack Surface Topology: {graph_data['root_domain']}[/bold cyan]")
    with db() as conn:
        assets = rows(conn.execute(
            """SELECT a.id, a.hostname, a.environment, r.total, r.band
               FROM scan_assets sa
               JOIN assets a ON a.id = sa.asset_id
               LEFT JOIN risk_scores r ON r.asset_id = a.id AND r.scan_id = sa.scan_id
               WHERE sa.scan_id = ?
               ORDER BY r.total DESC""",
            (args.scan,),
        ))

    for a in assets:
        sub_branch = tree.add(f"[bold]{a['hostname']}[/bold] [{band_badge(a['band'])} - Score: {a['total'] or 0}]")
        with db() as conn:
            dns_recs = rows(conn.execute(
                "SELECT record_type, value FROM dns_records WHERE scan_id = ? AND asset_id = ?",
                (args.scan, a["id"]),
            ))
            techs = rows(conn.execute(
                "SELECT name, category FROM technologies WHERE scan_id = ? AND asset_id = ?",
                (args.scan, a["id"]),
            ))
            findings = rows(conn.execute(
                "SELECT rule_id, severity, description FROM findings WHERE scan_id = ? AND asset_id = ?",
                (args.scan, a["id"]),
            ))

        if dns_recs:
            dns_branch = sub_branch.add("[bold yellow]DNS Records[/bold yellow]")
            for rec in dns_recs:
                dns_branch.add(f"{rec['record_type']}: {rec['value']}")

        if techs:
            tech_branch = sub_branch.add("[bold magenta]Technologies[/bold magenta]")
            for t in techs:
                tech_branch.add(f"{t['name']} ({t['category']})")

        if findings:
            find_branch = sub_branch.add("[bold red]Vulnerabilities[/bold red]")
            for f in findings:
                find_branch.add(f"{severity_badge(f['severity'])} {f['rule_id']}: {f['description']}")

    console.print(tree)
    return 0


def show_diff(args: argparse.Namespace) -> int:
    init()
    diff = calculate_scan_diff(args.scan_a, args.scan_b)
    console.print(Panel(
        f"[bold]Comparative Delta:[/bold] Scan #{args.scan_a} ➔ Scan #{args.scan_b}\n"
        f"[bold]Overall Posture Trend:[/bold] {diff['posture_trend']}\n"
        f"[bold]New Assets Discovered:[/bold] {len(diff['new_assets'])}\n"
        f"[bold]Decommissioned Assets:[/bold] {len(diff['removed_assets'])}\n"
        f"[bold]New Findings Introduced:[/bold] {len(diff['new_findings'])}\n"
        f"[bold]Findings Resolved:[/bold] {len(diff['resolved_findings'])}",
        title="[bold cyan]Attack Surface Comparative Delta[/bold cyan]",
        border_style="cyan"
    ))

    if diff["new_assets"]:
        console.print("[bold red]▶ Newly Discovered Assets (Potential Shadow IT):[/bold red]")
        for a in diff["new_assets"]:
            console.print(f"  • {a['hostname']} (Risk Score: {a['score'] or 0})")

    if diff["new_findings"]:
        console.print("\n[bold red]▶ New Security Regressions Introduced:[/bold red]")
        for f in diff["new_findings"]:
            console.print(f"  • {f['hostname']} -> {f['rule_id']}")

    if diff["resolved_findings"]:
        console.print("\n[bold green]✔ Security Findings Remediated:[/bold green]")
        for f in diff["resolved_findings"]:
            console.print(f"  • {f['hostname']} -> {f['rule_id']}")

    return 0


def run_copilot(args: argparse.Namespace) -> int:
    init()
    data = overview(args.scan)
    assets = data["assets"][:8]
    citations = [{"asset_id": a["id"], "hostname": a["hostname"], "score": a["total"] or 0, "band": a["band"], "environment": a["environment"]} for a in assets]
    if not assets:
        console.print("[bold yellow]No assets found for this scan to reason over.[/bold yellow]")
        return 1

    ai = provider()
    console.print(f"[dim]Analyzing scan #{args.scan} telemetry with {ai.name}...[/dim]\n")
    response = asyncio.run(ai.answer(args.query, citations))
    console.print(Panel(response, title="[bold cyan]Perimetryx Security Analyst[/bold cyan]", border_style="cyan"))
    return 0


def generate_report(args: argparse.Namespace) -> int:
    init()
    if args.format == "html":
        content = generate_html_report(args.scan)
    else:
        content = generate_markdown_report(args.scan)

    out_path = Path(args.output)
    out_path.write_text(content, encoding="utf-8")
    console.print(f"[bold green]✔ Successfully generated {args.format.upper()} audit report: {out_path}[/bold green]")
    return 0


def show_status(args: argparse.Namespace) -> int:
    data = scan_data(args.scan)
    print(json.dumps(data["scan"], indent=2, default=str))
    return 0


def show_priorities(args: argparse.Namespace) -> int:
    data = scan_data(args.scan)
    print(json.dumps(priority_plan(data["assets"], data["findings"]), indent=2, default=str))
    return 0


def show_roadmap(args: argparse.Namespace) -> int:
    data = scan_data(args.scan)
    plan = priority_plan(data["assets"], data["findings"])
    print(json.dumps({"priorities": plan, "roadmap": research_roadmap(plan)}, indent=2, default=str))
    return 0


def export_markdown(args: argparse.Namespace) -> int:
    args.format = "markdown"
    return generate_report(args)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="perimetryx", description="Perimetryx: Authorized Attack-Surface Intelligence")
    commands = root.add_subparsers(dest="command", required=True)

    init_scope = commands.add_parser("init-scope", help="Create a reviewable scope YAML configuration")
    init_scope.add_argument("--domain", required=True, help="Target root domain")
    init_scope.add_argument(
        "--authorization", choices=["owned_asset", "bug_bounty_program", "signed_engagement_letter"], required=True
    )
    init_scope.add_argument("--output", default="scope.yaml")
    init_scope.add_argument("--force", action="store_true")
    init_scope.set_defaults(handler=create_scope)

    scan = commands.add_parser("scan", help="Run an authorized attack surface reconnaissance sweep")
    scan.add_argument("target_domain", nargs="?", default=None, help="Direct domain to scan (e.g. example.com)")
    scan.add_argument("--domain", "-d", default=None, help="Direct domain to scan (e.g. example.com)")
    scan.add_argument("--scope", "-s", default=None, help="Path to scope.yaml (optional if domain is given)")
    scan.add_argument("--dry-run", action="store_true", help="Simulate without external probing")
    scan.add_argument("--confirm-authorization", action="store_true", help="Explicitly confirm target ownership or permission")
    scan.set_defaults(handler=run_scan)

    quick = commands.add_parser("quick-scan", help="Instantly scan any target domain (ideal for live teacher demos)")
    quick.add_argument("domain", help="Target root domain to scan dynamically (e.g. example.com)")
    quick.add_argument("--dry-run", action="store_true", help="Simulate without external probing")
    quick.set_defaults(handler=run_quick_scan)

    inspect = commands.add_parser("inspect", help="Inspect detailed asset telemetry and findings")
    inspect.add_argument("--scan", type=int, required=True, help="Scan ID")
    inspect.add_argument("--host", default=None, help="Specific hostname to inspect")
    inspect.set_defaults(handler=show_inspect)

    graph = commands.add_parser("graph", help="Render attack surface topology tree or export JSON")
    graph.add_argument("--scan", type=int, required=True, help="Scan ID")
    graph.add_argument("--json", action="store_true", help="Output raw nodes and edges JSON")
    graph.set_defaults(handler=show_graph)

    diff = commands.add_parser("diff", help="Calculate comparative delta between two scans")
    diff.add_argument("--scan-a", type=int, required=True, help="Baseline scan ID")
    diff.add_argument("--scan-b", type=int, required=True, help="Subsequent scan ID")
    diff.set_defaults(handler=show_diff)

    copilot = commands.add_parser("copilot", help="Query AI analyst over scan evidence")
    copilot.add_argument("--scan", type=int, required=True, help="Scan ID")
    copilot.add_argument("--query", required=True, help="Security question (e.g. 'What are the top 3 priorities?')")
    copilot.set_defaults(handler=run_copilot)

    report = commands.add_parser("report", help="Generate executive audit report (HTML or Markdown)")
    report.add_argument("--scan", type=int, required=True, help="Scan ID")
    report.add_argument("--format", choices=["markdown", "html"], default="html")
    report.add_argument("--output", default="perimetryx-audit-report.html")
    report.set_defaults(handler=generate_report)

    for name, handler, help_text in [
        ("status", show_status, "Show scan status and statistics"),
        ("prioritize", show_priorities, "Print evidence-backed manual review priorities"),
        ("roadmap", show_roadmap, "Print the responsible research roadmap for a scan"),
    ]:
        cmd = commands.add_parser(name, help=help_text)
        cmd.add_argument("--scan", type=int, required=True)
        cmd.set_defaults(handler=handler)

    export = commands.add_parser("export", help="Export review priorities as Markdown")
    export.add_argument("--scan", type=int, required=True)
    export.add_argument("--output", default="perimetryx-report.md")
    export.set_defaults(handler=export_markdown)

    return root


def main() -> int:
    init()
    if len(sys.argv) == 1:
        console.print(BANNER)
        parser().print_help()
        return 0
    args = parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())

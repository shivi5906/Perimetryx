"""Attack Surface Topology Graph Builder.

Generates relational nodes and edges mapping Domains, Subdomains, IP Addresses,
Web Technologies, and Security Findings.
"""

from __future__ import annotations

from typing import Any
from .store import db, load, rows


def build_attack_surface_graph(scan_id: int) -> dict[str, Any]:
    """Assemble an evidence graph linking Domain -> Assets -> IPs -> Tech -> Findings."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    seen_nodes: set[str] = set()

    def add_node(node_id: str, label: str, node_type: str, metadata: dict | None = None) -> None:
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {},
            })

    def add_edge(source: str, target: str, relationship: str) -> None:
        edges.append({"source": source, "target": target, "relationship": relationship})

    with db() as conn:
        scan_row = conn.execute(
            """SELECT s.id, d.root_domain 
               FROM scans s JOIN domains d ON d.id = s.domain_id 
               WHERE s.id = ?""",
            (scan_id,),
        ).fetchone()
        if not scan_row:
            return {"nodes": [], "edges": []}

        root_domain = scan_row["root_domain"]
        root_node_id = f"domain:{root_domain}"
        add_node(root_node_id, root_domain, "domain", {"root": True})

        # Fetch assets
        assets = rows(conn.execute(
            """SELECT a.id, a.hostname, a.environment, r.total as score, r.band, o.status_code, o.cname
               FROM scan_assets sa
               JOIN assets a ON a.id = sa.asset_id
               LEFT JOIN risk_scores r ON r.asset_id = a.id AND r.scan_id = sa.scan_id
               LEFT JOIN observations o ON o.asset_id = a.id AND o.scan_id = sa.scan_id
               WHERE sa.scan_id = ?""",
            (scan_id,),
        ))

        for asset in assets:
            asset_node_id = f"host:{asset['hostname']}"
            add_node(
                asset_node_id,
                asset["hostname"],
                "subdomain",
                {
                    "environment": asset["environment"],
                    "risk_score": asset["score"] or 0,
                    "band": asset["band"] or "low",
                    "status_code": asset["status_code"],
                },
            )
            add_edge(root_node_id, asset_node_id, "has_subdomain")

            # CNAME Aliases
            if asset.get("cname"):
                cname_node_id = f"cname:{asset['cname']}"
                add_node(cname_node_id, asset["cname"], "cname_alias")
                add_edge(asset_node_id, cname_node_id, "aliases_to")

            # DNS IP Records
            dns_records = rows(conn.execute(
                "SELECT record_type, value FROM dns_records WHERE scan_id = ? AND asset_id = ?",
                (scan_id, asset["id"]),
            ))
            for rec in dns_records:
                if rec["record_type"] in ("A", "AAAA"):
                    ip_node_id = f"ip:{rec['value']}"
                    add_node(ip_node_id, rec["value"], "ip_address")
                    add_edge(asset_node_id, ip_node_id, "resolves_to")

            # Technologies
            techs = rows(conn.execute(
                "SELECT name, category, version FROM technologies WHERE scan_id = ? AND asset_id = ?",
                (scan_id, asset["id"]),
            ))
            for tech in techs:
                tech_node_id = f"tech:{tech['name']}"
                label = f"{tech['name']} {tech['version']}" if tech.get("version") else tech["name"]
                add_node(tech_node_id, label, "technology", {"category": tech["category"]})
                add_edge(asset_node_id, tech_node_id, "runs_technology")

            # Findings
            findings = rows(conn.execute(
                """SELECT rule_id, category, severity, description, cvss_score, mitre_technique
                   FROM findings WHERE scan_id = ? AND asset_id = ?""",
                (scan_id, asset["id"]),
            ))
            for finding in findings:
                finding_node_id = f"finding:{asset['id']}:{finding['rule_id']}"
                add_node(
                    finding_node_id,
                    f"[{finding['severity'].upper()}] {finding['rule_id']}",
                    "finding",
                    {
                        "severity": finding["severity"],
                        "category": finding["category"],
                        "cvss": finding["cvss_score"],
                        "mitre": finding["mitre_technique"],
                    },
                )
                add_edge(asset_node_id, finding_node_id, "vulnerable_to")

    return {
        "scan_id": scan_id,
        "root_domain": root_domain,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "assets": len(assets),
        },
        "nodes": nodes,
        "edges": edges,
    }

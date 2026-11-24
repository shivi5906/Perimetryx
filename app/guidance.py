"""Human-readable, evidence-driven guidance for authorized manual assessment."""

from __future__ import annotations

from collections import defaultdict

PLAYBOOKS = {
    "staging_exposed": {
        "priority": "High",
        "objective": "Confirm the asset is intended to be publicly reachable and is within program scope.",
        "safe_checks": [
            "Confirm the hostname is explicitly in scope before opening it in a browser.",
            "Use only a program-authorized test account; do not test production merchants or other users.",
            "Record authentication behavior and visible environment identifiers without attempting credential attacks.",
        ],
    },
    "dev_exposed": {
        "priority": "High",
        "objective": "Determine whether the development-labelled host exposes an authorized test surface.",
        "safe_checks": [
            "Recheck scope and exclusions before any interaction.",
            "Review public response metadata and login boundaries using a test account only.",
            "Stop if the host belongs to a third party or displays customer data.",
        ],
    },
    "missing_security_header": {
        "priority": "Medium",
        "objective": "Assess whether the observed header absence creates a program-eligible impact in this application.",
        "safe_checks": [
            "Reproduce the response once and preserve the response headers as evidence.",
            "Read program exclusions; missing headers alone are commonly informational.",
            "Only report it if you can demonstrate permitted, concrete impact without accessing another user's data.",
        ],
    },
    "admin_surface": {
        "priority": "Medium",
        "objective": "Identify whether the administrative-looking host is in scope and correctly protected.",
        "safe_checks": [
            "Confirm scope before opening the root page.",
            "Observe the login and access-control boundary with your own authorized account.",
            "Do not guess credentials, enumerate accounts, or probe hidden paths.",
        ],
    },
}


DEFAULT_PLAYBOOK = {
    "priority": "Review",
    "objective": "Validate the recorded observation against the program policy.",
    "safe_checks": [
        "Confirm the exact asset is in scope.",
        "Preserve the observation as evidence.",
        "Use only an authorized test account and stop if real-user data appears.",
    ],
}


def priority_plan(assets: list[dict], findings: list[dict]) -> list[dict]:
    findings_by_asset: dict[int, list[dict]] = defaultdict(list)
    for finding in findings:
        findings_by_asset[finding["asset_id"]].append(finding)

    plan = []
    for asset in assets:
        asset_findings = findings_by_asset.get(asset["id"], [])
        for finding in asset_findings:
            playbook = PLAYBOOKS.get(finding["category"], DEFAULT_PLAYBOOK)
            plan.append(
                {
                    "hostname": asset["hostname"],
                    "risk_score": asset["total"] or 0,
                    "finding": finding["description"],
                    "classification": finding["classification"],
                    "priority": playbook["priority"],
                    "objective": playbook["objective"],
                    "safe_checks": playbook["safe_checks"],
                    "evidence": finding["evidence"],
                }
            )
    return sorted(plan, key=lambda item: item["risk_score"], reverse=True)


def research_roadmap(plan: list[dict]) -> list[dict]:
    steps = [
        {
            "phase": "1. Scope and account setup",
            "success_criteria": "The exact hostname is in scope and a program-approved test account exists.",
        },
        {
            "phase": "2. Evidence triage",
            "success_criteria": "You can explain each selected asset's score using stored DNS, HTTP, and finding evidence.",
        },
        {
            "phase": "3. Manual verification",
            "success_criteria": "A safe, reproducible behavior is observed without brute force, exploitation, or access to another user's data.",
        },
        {
            "phase": "4. Impact validation",
            "success_criteria": "The behavior has concrete, in-scope security impact under the program's rules; otherwise stop and document it as informational.",
        },
        {
            "phase": "5. Responsible report",
            "success_criteria": "The report contains exact steps, redacted evidence, impact, remediation context, and no AI-invented claims.",
        },
    ]
    if not plan:
        steps.insert(
            1,
            {
                "phase": "1a. Improve coverage",
                "success_criteria": "Run an authorized scan after confirming wildcards and exclusions in the current program scope.",
            },
        )
    return steps

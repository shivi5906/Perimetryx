from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .schemas import AssetInput, CopilotQuestion, DomainCreate, FindingInput, ScanCreate
from .ai import provider
from .scope_guard import allowed, normalize
from .scoring import score
from .store import db, dump, init, load, now, rows

app = FastAPI(title="Perimetryx API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:8000"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup(): init()

def domain_or_404(domain_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
    if not row: raise HTTPException(404, "Domain not found")
    result = dict(row); result["scope"] = load(result.pop("scope_json")); return result

def scan_or_404(scan_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row: raise HTTPException(404, "Scan not found")
    return dict(row)

@app.get("/api/health")
def health(): return {"status": "ok", "version": app.version}

@app.post("/api/domains", status_code=201)
def create_domain(body: DomainCreate):
    if normalize(body.root_domain) != body.scope.domain:
        raise HTTPException(422, "root_domain must match scope.domain")
    if body.scope.domain not in body.scope.allowed_domains:
        raise HTTPException(422, "The root domain must be explicitly allowed")
    with db() as conn:
        try:
            cursor = conn.execute("INSERT INTO domains(root_domain, scope_json, created_at) VALUES (?, ?, ?)", (body.scope.domain, dump(body.scope.model_dump()), now()))
        except Exception as error:
            raise HTTPException(409, "Domain already exists") from error
        return {"id": cursor.lastrowid, "root_domain": body.scope.domain, "scope": body.scope}

@app.get("/api/domains")
def list_domains():
    with db() as conn: return rows(conn.execute("SELECT id, root_domain, created_at FROM domains ORDER BY id DESC"))

@app.get("/api/domains/{domain_id}")
def get_domain(domain_id: int): return domain_or_404(domain_id)

@app.post("/api/domains/{domain_id}/scans", status_code=201)
def create_scan(domain_id: int, body: ScanCreate):
    domain = domain_or_404(domain_id)
    with db() as conn:
        cursor = conn.execute("INSERT INTO scans(domain_id, status, dry_run, started_at) VALUES (?, 'running', ?, ?)", (domain_id, body.dry_run, now()))
        scan_id = cursor.lastrowid
        conn.execute("INSERT INTO audit_events(scan_id, at, action, target, result) VALUES (?, ?, 'scan_started', ?, ?)", (scan_id, now(), domain["root_domain"], "dry-run" if body.dry_run else "authorized"))
        return {"id": scan_id, "status": "running", "dry_run": body.dry_run}

@app.post("/api/scans/{scan_id}/assets", status_code=201)
def add_asset(scan_id: int, body: AssetInput):
    scan = scan_or_404(scan_id); domain = domain_or_404(scan["domain_id"])
    from .schemas import ScopeConfig
    in_scope, reason = allowed(body.hostname, ScopeConfig(**domain["scope"]))
    if not in_scope:
        with db() as conn: conn.execute("INSERT INTO audit_events(scan_id, at, action, target, result) VALUES (?, ?, 'scope_denied', ?, ?)", (scan_id, now(), body.hostname, reason))
        raise HTTPException(403, {"reason": reason, "hostname": body.hostname})
    host = normalize(body.hostname)
    with db() as conn:
        existing = conn.execute("SELECT id FROM assets WHERE domain_id = ? AND hostname = ?", (domain["id"], host)).fetchone()
        if existing: asset_id, change = existing["id"], "persisted"
        else:
            asset_id = conn.execute("INSERT INTO assets(domain_id, hostname, source, environment, first_seen_scan_id, last_seen_scan_id) VALUES (?, ?, ?, ?, ?, ?)", (domain["id"], host, body.source, body.environment, scan_id, scan_id)).lastrowid; change = "new"
        conn.execute("UPDATE assets SET last_seen_scan_id=?, environment=? WHERE id=?", (scan_id, body.environment, asset_id))
        conn.execute("INSERT OR REPLACE INTO scan_assets(scan_id, asset_id, status) VALUES (?, ?, ?)", (scan_id, asset_id, change))
        conn.execute("INSERT INTO observations(scan_id, asset_id, status_code, title, headers_json, cname) VALUES (?, ?, ?, ?, ?, ?)", (scan_id, asset_id, body.status_code, body.title, dump(body.headers), body.cname))
    return {"asset_id": asset_id, "hostname": host, "scan_status": change, "scope": reason}

@app.post("/api/scans/{scan_id}/assets/{asset_id}/findings", status_code=201)
def add_finding(scan_id: int, asset_id: int, body: FindingInput):
    scan_or_404(scan_id)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM scan_assets WHERE scan_id=? AND asset_id=?", (scan_id, asset_id)).fetchone(): raise HTTPException(404, "Asset is not part of this scan")
        finding_id = conn.execute("INSERT INTO findings(scan_id, asset_id, rule_id, category, classification, description, evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?)", (scan_id, asset_id, body.rule_id, body.category, body.classification, body.description, dump(body.evidence))).lastrowid
    recompute_score(scan_id, asset_id)
    return {"id": finding_id}

def recompute_score(scan_id: int, asset_id: int):
    with db() as conn:
        asset = conn.execute("SELECT environment FROM assets WHERE id=?", (asset_id,)).fetchone()
        findings = rows(conn.execute("SELECT category FROM findings WHERE scan_id=? AND asset_id=?", (scan_id, asset_id)))
        total, band, breakdown = score(findings, asset["environment"])
        conn.execute("INSERT OR REPLACE INTO risk_scores(scan_id, asset_id, total, band, breakdown_json) VALUES (?, ?, ?, ?, ?)", (scan_id, asset_id, total, band, dump(breakdown)))

@app.post("/api/scans/{scan_id}/complete")
def complete_scan(scan_id: int):
    scan_or_404(scan_id)
    with db() as conn:
        asset_ids = rows(conn.execute("SELECT asset_id FROM scan_assets WHERE scan_id=?", (scan_id,)))
    for record in asset_ids: recompute_score(scan_id, record["asset_id"])
    with db() as conn:
        stats = {"assets": len(asset_ids), "findings": conn.execute("SELECT COUNT(*) FROM findings WHERE scan_id=?", (scan_id,)).fetchone()[0]}
        conn.execute("UPDATE scans SET status='completed', completed_at=?, stats_json=? WHERE id=?", (now(), dump(stats), scan_id))
        return {"id": scan_id, "status": "completed", "stats": stats}

@app.get("/api/scans/{scan_id}/overview")
def overview(scan_id: int):
    scan = scan_or_404(scan_id)
    with db() as conn:
        assets = rows(conn.execute("""SELECT a.id, a.hostname, a.environment, a.source, sa.status AS change_status, o.status_code, o.title, r.total, r.band, r.breakdown_json
            FROM scan_assets sa JOIN assets a ON a.id=sa.asset_id LEFT JOIN observations o ON o.asset_id=a.id AND o.scan_id=sa.scan_id LEFT JOIN risk_scores r ON r.asset_id=a.id AND r.scan_id=sa.scan_id
            WHERE sa.scan_id=? ORDER BY COALESCE(r.total, 0) DESC, a.hostname""", (scan_id,)))
        findings = rows(conn.execute("SELECT f.*, a.hostname FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.scan_id=? ORDER BY f.id DESC", (scan_id,)))
    for asset in assets: asset["breakdown"] = load(asset.pop("breakdown_json"))
    for finding in findings: finding["evidence"] = load(finding.pop("evidence_json"))
    return {"scan": scan, "assets": assets, "findings": findings}

@app.get("/api/scans/{scan_id}/graph")
def graph(scan_id: int):
    scan_or_404(scan_id)
    with db() as conn:
        data = rows(conn.execute("""SELECT a.id, a.hostname, a.environment, o.cname, r.total, r.band FROM scan_assets sa JOIN assets a ON a.id=sa.asset_id
        LEFT JOIN observations o ON o.asset_id=a.id AND o.scan_id=sa.scan_id LEFT JOIN risk_scores r ON r.asset_id=a.id AND r.scan_id=sa.scan_id WHERE sa.scan_id=?""", (scan_id,)))
    nodes, edges = [], []
    for asset in data:
        nodes.append({"id": f"asset-{asset['id']}", "label": asset["hostname"], "type": "asset", "risk": asset["band"] or "low"})
        if asset["cname"]:
            node = f"cname-{asset['cname']}"; nodes.append({"id": node, "label": asset["cname"], "type": "cname"}); edges.append({"source": f"asset-{asset['id']}", "target": node, "label": "CNAME"})
    return {"nodes": nodes, "edges": edges}

@app.get("/api/scans/{scan_id}/diff")
def history_diff(scan_id: int):
    scan = scan_or_404(scan_id)
    with db() as conn:
        previous = conn.execute("SELECT id FROM scans WHERE domain_id=? AND status='completed' AND id < ? ORDER BY id DESC LIMIT 1", (scan["domain_id"], scan_id)).fetchone()
        current = {r["hostname"] for r in rows(conn.execute("SELECT a.hostname FROM scan_assets sa JOIN assets a ON a.id=sa.asset_id WHERE sa.scan_id=?", (scan_id,)))}
        before = set() if not previous else {r["hostname"] for r in rows(conn.execute("SELECT a.hostname FROM scan_assets sa JOIN assets a ON a.id=sa.asset_id WHERE sa.scan_id=?", (previous["id"],)))}
    return {"from_scan_id": previous["id"] if previous else None, "to_scan_id": scan_id, "new_assets": sorted(current-before), "removed_assets": sorted(before-current), "persisted_assets": sorted(current & before)}

@app.post("/api/scans/{scan_id}/copilot")
async def copilot(scan_id: int, body: CopilotQuestion):
    data = overview(scan_id); assets = data["assets"][:5]
    citations = [{"asset_id": a["id"], "hostname": a["hostname"], "score": a["total"] or 0} for a in assets]
    if not assets: return {"answer": "No assets have been recorded for this scan yet.", "citations": []}
    selected = provider()
    try: answer = await selected.answer(body.question, citations)
    except Exception as error: raise HTTPException(502, "Configured AI provider did not return an answer") from error
    return {"answer": answer, "citations": citations, "grounded": True, "model": selected.name}

STATIC = Path(__file__).parent.parent / "web"
app.mount("/", StaticFiles(directory=STATIC, html=True), name="web")

import asyncio
import json
import time
import uuid
from typing import Any, Literal

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

router = APIRouter()

# In-memory recent alerts buffer (circular buffer of 50 items)
_RECENT_ALERTS: list[dict[str, Any]] = []
_MAX_RECENT = 50


class AlertConnectionManager:
    def __init__(self):
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]):
        dead_connections = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.add(connection)
        for dead in dead_connections:
            self.active_connections.discard(dead)


manager = AlertConnectionManager()


class AlertWebhookRequest(BaseModel):
    format: Literal["crowdstrike", "defender", "guardduty", "splunk", "beyondlabs", "generic"] = "generic"
    title: str = Field(..., min_length=1)
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    source: str = "Enterprise Webhook"
    description: str = ""
    iocs: list[str] = Field(default_factory=list)
    host: str | None = None
    user: str | None = None
    technique: str | None = None
    raw_payload: dict[str, Any] | None = None


class SimulateRequest(BaseModel):
    scenario: Literal["apt29", "volt_typhoon", "ransomware", "random"] = "apt29"
    count: int = Field(default=3, ge=1, le=10)


def _record_alert(alert: dict[str, Any]):
    _RECENT_ALERTS.append(alert)
    if len(_RECENT_ALERTS) > _MAX_RECENT:
        _RECENT_ALERTS.pop(0)


@router.post("/webhook")
async def ingest_webhook(payload: AlertWebhookRequest):
    alert_id = f"alert-{uuid.uuid4().hex[:12]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    normalized = {
        "id": alert_id,
        "title": payload.title,
        "severity": payload.severity,
        "format": payload.format,
        "source": payload.source,
        "description": payload.description,
        "iocs": payload.iocs,
        "host": payload.host,
        "user": payload.user,
        "technique": payload.technique,
        "timestamp": now_iso,
        "raw_payload": payload.raw_payload or {},
    }

    _record_alert(normalized)
    await manager.broadcast({"type": "alert", "data": normalized})

    return {
        "status": "ingested",
        "alert_id": alert_id,
        "subscribers": len(manager.active_connections),
        "timestamp": now_iso,
    }


@router.get("/recent")
def get_recent_alerts():
    return {
        "total": len(_RECENT_ALERTS),
        "alerts": list(reversed(_RECENT_ALERTS)),
    }


@router.websocket("/ws")
async def websocket_alerts_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial greeting and backlog
        await websocket.send_json({
            "type": "welcome",
            "message": "Connected to BeyondLabs Real-Time Alert Ingestion Stream",
            "active_subscribers": len(manager.active_connections),
            "recent_count": len(_RECENT_ALERTS),
        })

        # Keep-alive loop listening for client pings
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_json({"type": "pong", "ts": time.time()})
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


SIMULATION_SCENARIOS = {
    "apt29": [
        {
            "title": "Adversary-in-the-Middle (AitM) Session Token Replay",
            "severity": "high",
            "format": "defender",
            "source": "Microsoft Defender for Cloud Apps",
            "technique": "T1566.002",
            "host": "WS-014",
            "user": "alex.chen@corp.beyondlabs.io",
            "iocs": ["198.51.100.45", "login.microsoftonline.evil-auth.net"],
            "description": "Stolen Azure AD PRT session cookie replayed from anomalous ASN in St. Petersburg.",
        },
        {
            "title": "Anomalous Azure Multi-Tenant App Consent Grant",
            "severity": "critical",
            "format": "defender",
            "source": "Microsoft Entra ID Audit",
            "technique": "T1528",
            "host": "Cloud-Tenant-US",
            "user": "alex.chen@corp.beyondlabs.io",
            "iocs": ["app-id-7a91bf32"],
            "description": "Suspicious OAuth app granted Mail.ReadWrite and Offline_Access privileges.",
        },
        {
            "title": "M365 Mailbox Exfiltration via Graph API Sweep",
            "severity": "high",
            "format": "splunk",
            "source": "Splunk Enterprise Security",
            "technique": "T1114.002",
            "host": "Cloud-Tenant-US",
            "user": "ServicePrincipal-Sync",
            "iocs": ["198.51.100.45"],
            "description": "Mass download of executive mailbox contents and sensitive attachments.",
        },
    ],
    "volt_typhoon": [
        {
            "title": "Living-off-the-Land (LOLBin) Fast-Flux DNS Tunneling",
            "severity": "high",
            "format": "crowdstrike",
            "source": "CrowdStrike Falcon Endpoint",
            "technique": "T1071.004",
            "host": "SCADA-GW-01",
            "user": "NT AUTHORITY\\SYSTEM",
            "iocs": ["203.0.113.88", "c2.grid-sync.internal-telemetry.org"],
            "description": "High-frequency subdomains resolved by certutil.exe indicating C2 data channel.",
        },
        {
            "title": "Active Directory SharpHound LDAP Scoping Sweep",
            "severity": "medium",
            "format": "splunk",
            "source": "Windows Security EventLog (EID 1644)",
            "technique": "T1087.002",
            "host": "DC-PRIMARY",
            "user": "svc_backup",
            "iocs": ["10.0.4.15"],
            "description": "Rapid LDAP enumeration querying all Domain Controller computer accounts.",
        },
        {
            "title": "PsExec Lateral Movement to Substation Gateway",
            "severity": "critical",
            "format": "crowdstrike",
            "source": "CrowdStrike Falcon Insight",
            "technique": "T1569.002",
            "host": "SUBSTATION-03",
            "user": "ADMINISTRATOR",
            "iocs": ["10.0.4.15", "PSEXESVC.exe"],
            "description": "Remote service creation and IPC$ admin share mount on industrial gateway.",
        },
    ],
    "ransomware": [
        {
            "title": "Volume Shadow Copy Deletion via VSSAdmin",
            "severity": "critical",
            "format": "defender",
            "source": "Microsoft Defender for Endpoint",
            "technique": "T1490",
            "host": "FS-CORP-02",
            "user": "svc_admin",
            "iocs": ["vssadmin.exe", "wmic.exe"],
            "description": "Command-line invocation of 'vssadmin delete shadows /all /quiet' prior to staging.",
        },
        {
            "title": "Data Staging in Multi-Volume 7-Zip Archive",
            "severity": "high",
            "format": "beyondlabs",
            "source": "BeyondLabs Detection Sandbox",
            "technique": "T1560.001",
            "host": "FS-CORP-02",
            "user": "svc_admin",
            "iocs": ["7z.exe", "C:\\Windows\\Temp\\fin_stage.7z"],
            "description": "Archival utility password-protecting finance directory with switch -mhe=on.",
        },
        {
            "title": "Ransomware File Extension Renaming Outbreak",
            "severity": "critical",
            "format": "guardduty",
            "source": "AWS GuardDuty S3 Protection",
            "technique": "T1486",
            "host": "AWS-S3-Backups",
            "user": "AWS-Backup-Service",
            "iocs": ["s3://corp-backups-2026/"],
            "description": "Rapid modification and appending of '.alphv' extension to production objects.",
        },
    ],
}


@router.post("/simulate")
async def simulate_burst(req: SimulateRequest):
    scenario_key = req.scenario
    if scenario_key == "random":
        import random
        scenario_key = random.choice(["apt29", "volt_typhoon", "ransomware"])

    templates = SIMULATION_SCENARIOS.get(scenario_key, SIMULATION_SCENARIOS["apt29"])
    generated: list[dict[str, Any]] = []

    count = min(req.count, len(templates))
    now = time.time()

    for i in range(count):
        tpl = templates[i]
        alert_id = f"sim-{uuid.uuid4().hex[:10]}"
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - (count - i) * 30))

        item = {
            "id": alert_id,
            "title": tpl["title"],
            "severity": tpl["severity"],
            "format": tpl["format"],
            "source": tpl["source"],
            "technique": tpl["technique"],
            "host": tpl["host"],
            "user": tpl["user"],
            "iocs": tpl["iocs"],
            "description": tpl["description"],
            "timestamp": iso,
            "simulated": True,
            "scenario": scenario_key,
        }

        _record_alert(item)
        generated.append(item)
        # Broadcast asynchronously to subscribers
        await manager.broadcast({"type": "alert", "data": item})

    return {
        "status": "simulated",
        "scenario": scenario_key,
        "count": len(generated),
        "alerts": generated,
    }

import { type Severity } from "@/lib/severity";

export interface StreamingAlert {
  id: string;
  title: string;
  severity: Severity;
  format: "crowdstrike" | "defender" | "guardduty" | "splunk" | "beyondlabs" | "generic";
  source: string;
  timestamp: string;
  description?: string;
  technique?: string;
  host?: string;
  user?: string;
  iocs?: string[];
  simulated?: boolean;
}

export type StreamScenario = "apt29" | "volt_typhoon" | "ransomware" | "random";

const LS_AUDIO_MUTED = "ba.streaming.muted";
const LS_STREAM_ACTIVE = "ba.streaming.active";

// Realistic fallback alerts if offline or running in standalone frontend
const FALLBACK_SCENARIOS: Record<string, Omit<StreamingAlert, "id" | "timestamp">[]> = {
  apt29: [
    {
      title: "Adversary-in-the-Middle (AitM) Session Replay",
      severity: "high",
      format: "defender",
      source: "Microsoft Defender for Cloud Apps",
      technique: "T1566.002",
      host: "WS-014",
      user: "alex.chen@corp.beyondlabs.io",
      iocs: ["198.51.100.45", "login.microsoftonline.evil-auth.net"],
      description: "Stolen Azure AD PRT session cookie replayed from foreign ASN.",
    },
    {
      title: "Anomalous Azure Multi-Tenant App Consent Grant",
      severity: "critical",
      format: "defender",
      source: "Microsoft Entra ID Audit",
      technique: "T1528",
      host: "Cloud-Tenant-US",
      user: "alex.chen@corp.beyondlabs.io",
      iocs: ["app-id-7a91bf32"],
      description: "Suspicious OAuth app granted Mail.ReadWrite and Offline_Access.",
    },
    {
      title: "M365 Mailbox Exfiltration via Graph API Sweep",
      severity: "high",
      format: "splunk",
      source: "Splunk Enterprise Security",
      technique: "T1114.002",
      host: "Cloud-Tenant-US",
      user: "ServicePrincipal-Sync",
      iocs: ["198.51.100.45"],
      description: "Mass download of executive mailbox contents and sensitive attachments.",
    },
  ],
  volt_typhoon: [
    {
      title: "Living-off-the-Land (LOLBin) Fast-Flux DNS Tunneling",
      severity: "high",
      format: "crowdstrike",
      source: "CrowdStrike Falcon Endpoint",
      technique: "T1071.004",
      host: "SCADA-GW-01",
      user: "NT AUTHORITY\\SYSTEM",
      iocs: ["203.0.113.88", "c2.grid-sync.internal-telemetry.org"],
      description: "High-frequency subdomains resolved by certutil.exe indicating C2 data channel.",
    },
    {
      title: "Active Directory SharpHound LDAP Scoping Sweep",
      severity: "medium",
      format: "splunk",
      source: "Windows Security EventLog (EID 1644)",
      technique: "T1087.002",
      host: "DC-PRIMARY",
      user: "svc_backup",
      iocs: ["10.0.4.15"],
      description: "Rapid LDAP enumeration querying domain computer accounts.",
    },
    {
      title: "PsExec Lateral Movement to Substation Gateway",
      severity: "critical",
      format: "crowdstrike",
      source: "CrowdStrike Falcon Insight",
      technique: "T1569.002",
      host: "SUBSTATION-03",
      user: "ADMINISTRATOR",
      iocs: ["10.0.4.15", "PSEXESVC.exe"],
      description: "Remote service creation and IPC$ admin share mount on industrial gateway.",
    },
  ],
  ransomware: [
    {
      title: "Volume Shadow Copy Deletion via VSSAdmin",
      severity: "critical",
      format: "defender",
      source: "Microsoft Defender for Endpoint",
      technique: "T1490",
      host: "FS-CORP-02",
      user: "svc_admin",
      iocs: ["vssadmin.exe", "wmic.exe"],
      description: "Command-line invocation of 'vssadmin delete shadows /all /quiet'.",
    },
    {
      title: "Data Staging in Multi-Volume 7-Zip Archive",
      severity: "high",
      format: "beyondlabs",
      source: "BeyondLabs Detection Sandbox",
      technique: "T1560.001",
      host: "FS-CORP-02",
      user: "svc_admin",
      iocs: ["7z.exe", "C:\\Windows\\Temp\\fin_stage.7z"],
      description: "Archival utility password-protecting finance directory with switch -mhe=on.",
    },
    {
      title: "Ransomware File Extension Renaming Outbreak",
      severity: "critical",
      format: "guardduty",
      source: "AWS GuardDuty S3 Protection",
      technique: "T1486",
      host: "AWS-S3-Backups",
      user: "AWS-Backup-Service",
      iocs: ["s3://corp-backups-2026/"],
      description: "Rapid modification and appending of '.alphv' extension to production objects.",
    },
  ],
};

// Pure Web Audio API Synthesizer (No MP3/WAV files required)
class CyberAudioSynthesizer {
  private ctx: AudioContext | null = null;

  private getContext(): AudioContext | null {
    if (typeof window === "undefined") return null;
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (AudioCtx) this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === "suspended") {
      this.ctx.resume().catch(() => {});
    }
    return this.ctx;
  }

  playAlertPing(severity: Severity) {
    try {
      if (isAudioMuted()) return;
      const ctx = this.getContext();
      if (!ctx) return;

      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.connect(gain);
      gain.connect(ctx.destination);

      const now = ctx.currentTime;
      if (severity === "critical") {
        // High urgency two-tone alert
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.exponentialRampToValueAtTime(440, now + 0.15);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
        osc.start(now);
        osc.stop(now + 0.2);
      } else if (severity === "high") {
        // High priority cyber ping
        osc.type = "sine";
        osc.frequency.setValueAtTime(660, now);
        osc.frequency.exponentialRampToValueAtTime(330, now + 0.12);
        gain.gain.setValueAtTime(0.05, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
        osc.start(now);
        osc.stop(now + 0.15);
      } else {
        // Low subtle tick
        osc.type = "triangle";
        osc.frequency.setValueAtTime(520, now);
        gain.gain.setValueAtTime(0.03, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
        osc.start(now);
        osc.stop(now + 0.08);
      }
    } catch {
      // Ignore audio synthesis errors
    }
  }
}

export const cyberAudio = new CyberAudioSynthesizer();

export function isAudioMuted(): boolean {
  try {
    return localStorage.getItem(LS_AUDIO_MUTED) === "true";
  } catch {
    return false;
  }
}

export function setAudioMuted(muted: boolean) {
  try {
    localStorage.setItem(LS_AUDIO_MUTED, String(muted));
    window.dispatchEvent(new CustomEvent("ba:streaming-muted-changed", { detail: muted }));
  } catch {}
}

export function isStreamingActive(): boolean {
  try {
    const val = localStorage.getItem(LS_STREAM_ACTIVE);
    return val === null ? true : val === "true";
  } catch {
    return true;
  }
}

export function setStreamingActive(active: boolean) {
  try {
    localStorage.setItem(LS_STREAM_ACTIVE, String(active));
    window.dispatchEvent(new CustomEvent("ba:streaming-active-changed", { detail: active }));
  } catch {}
}

/** Streaming Ingestion Client Manager */
class StreamingIngestClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private listeners: Set<(alert: StreamingAlert) => void> = new Set();
  private recentAlerts: StreamingAlert[] = [];
  private isConnected = false;

  constructor() {
    if (typeof window !== "undefined") {
      this.init();
    }
  }

  private init() {
    this.connectWs();
  }

  private getWsUrl(): string {
    if (typeof window === "undefined") return "ws://127.0.0.1:8000/api/alerts/ws";
    const loc = window.location;
    const proto = loc.protocol === "https:" ? "wss:" : "ws:";
    // If running on Vite dev port 5173, backend is on 8000
    if (loc.port === "5173") {
      return `${proto}//${loc.hostname}:8000/api/alerts/ws`;
    }
    return `${proto}//${loc.host}/api/alerts/ws`;
  }

  private connectWs() {
    try {
      const url = this.getWsUrl();
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        this.isConnected = true;
      };

      this.ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === "alert" && msg.data) {
            this.handleIncomingAlert(msg.data);
          }
        } catch {}
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.isConnected = false;
      };
    } catch {
      this.isConnected = false;
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      this.connectWs();
    }, 5000);
  }

  private handleIncomingAlert(raw: any) {
    const alert: StreamingAlert = {
      id: raw.id || `alert-${Date.now().toString(36)}`,
      title: raw.title || "Unclassified Threat Event",
      severity: raw.severity || "medium",
      format: raw.format || "generic",
      source: raw.source || "Streaming Ingest",
      timestamp: raw.timestamp || new Date().toISOString(),
      description: raw.description,
      technique: raw.technique,
      host: raw.host,
      user: raw.user,
      iocs: raw.iocs || [],
      simulated: raw.simulated,
    };

    this.recentAlerts.unshift(alert);
    if (this.recentAlerts.length > 50) this.recentAlerts.pop();

    // Play subtle cyber tone if audio is unmuted
    cyberAudio.playAlertPing(alert.severity);

    // Notify registered in-memory subscribers
    for (const listener of this.listeners) {
      try {
        listener(alert);
      } catch {}
    }

    // Broadcast global DOM event for multi-component syncing
    try {
      window.dispatchEvent(new CustomEvent("ba:streaming-alert-received", { detail: alert }));
    } catch {}
  }

  subscribe(listener: (alert: StreamingAlert) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  getRecent(): StreamingAlert[] {
    return [...this.recentAlerts];
  }

  getStatus(): { connected: boolean; subscribers: number; cachedCount: number } {
    return {
      connected: this.isConnected,
      subscribers: this.listeners.size,
      cachedCount: this.recentAlerts.length,
    };
  }

  /** Trigger an enterprise threat burst via backend simulation or local fallback */
  async triggerSimulationBurst(scenario: StreamScenario = "apt29", count = 3): Promise<StreamingAlert[]> {
    try {
      const res = await fetch("/api/alerts/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario, count }),
      });
      if (res.ok) {
        const data = await res.json();
        return data.alerts || [];
      }
    } catch {
      // Fall through to client-side fallback
    }

    // Local simulation fallback
    const key = scenario === "random" ? "apt29" : scenario;
    const tpls = FALLBACK_SCENARIOS[key] || FALLBACK_SCENARIOS.apt29;
    const generated: StreamingAlert[] = [];

    for (let i = 0; i < Math.min(count, tpls.length); i++) {
      const t = tpls[i];
      const alert: StreamingAlert = {
        ...t,
        id: `local-sim-${Math.random().toString(36).slice(2, 10)}`,
        timestamp: new Date(Date.now() - (count - i) * 20000).toISOString(),
        simulated: true,
      };
      this.handleIncomingAlert(alert);
      generated.push(alert);
    }

    return generated;
  }
}

export const streamingIngestClient = new StreamingIngestClient();

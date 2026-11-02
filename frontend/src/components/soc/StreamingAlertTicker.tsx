import { useState, useEffect, useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  Radio,
  Volume2,
  VolumeX,
  Play,
  Pause,
  Sparkles,
  ArrowRight,
  ShieldAlert,
  ChevronDown,
  Layers,
  Flame,
  Zap,
} from "lucide-react";
import {
  streamingIngestClient,
  isAudioMuted,
  setAudioMuted,
  isStreamingActive,
  setStreamingActive,
  type StreamingAlert,
  type StreamScenario,
} from "@/lib/alerts/streaming-ingest";
import { notify } from "@/lib/notify";

const VENDOR_STYLES: Record<string, { label: string; color: string; border: string }> = {
  crowdstrike: { label: "CrowdStrike Falcon", color: "text-red-400 bg-red-500/10", border: "border-red-500/30" },
  defender: { label: "Microsoft Defender", color: "text-sky-400 bg-sky-500/10", border: "border-sky-500/30" },
  guardduty: { label: "AWS GuardDuty", color: "text-amber-400 bg-amber-500/10", border: "border-amber-500/30" },
  splunk: { label: "Splunk HEC", color: "text-orange-400 bg-orange-500/10", border: "border-orange-500/30" },
  beyondlabs: { label: "BeyondLabs EDR", color: "text-emerald-400 bg-emerald-500/10", border: "border-emerald-500/30" },
  generic: { label: "Enterprise Ingest", color: "text-primary bg-primary/10", border: "border-primary/30" },
};

export function StreamingAlertTicker() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<StreamingAlert[]>(() => streamingIngestClient.getRecent());
  const [active, setActive] = useState<boolean>(() => isStreamingActive());
  const [muted, setMuted] = useState<boolean>(() => isAudioMuted());
  const [scenarioOpen, setScenarioOpen] = useState(false);
  const [simulating, setSimulating] = useState(false);

  useEffect(() => {
    const unsub = streamingIngestClient.subscribe((newAlert) => {
      setAlerts((prev) => [newAlert, ...prev.slice(0, 19)]);
    });

    // Populate initial alert if empty
    if (alerts.length === 0) {
      streamingIngestClient.triggerSimulationBurst("apt29", 1).then((res) => {
        if (res.length > 0) setAlerts(res);
      });
    }

    return () => unsub();
  }, []);

  const latestAlert = alerts[0] || null;

  const handleToggleStream = () => {
    const next = !active;
    setActive(next);
    setStreamingActive(next);
    notify.info(next ? "Live alert stream resumed" : "Live alert stream paused");
  };

  const handleToggleMute = () => {
    const next = !muted;
    setMuted(next);
    setAudioMuted(next);
    notify.info(next ? "Alert telemetry audio muted" : "Alert telemetry audio active");
  };

  const handleTriggerBurst = async (scenario: StreamScenario) => {
    setSimulating(true);
    setScenarioOpen(false);
    try {
      const burst = await streamingIngestClient.triggerSimulationBurst(scenario, 3);
      notify.success(`Ingested ${burst.length} live telemetry alerts (${scenario.toUpperCase()})`);
    } catch {
      notify.error("Simulation burst failed");
    } finally {
      setSimulating(false);
    }
  };

  const vendor = latestAlert ? VENDOR_STYLES[latestAlert.format] || VENDOR_STYLES.generic : VENDOR_STYLES.generic;

  return (
    <div
      id="streaming-alert-ticker"
      className="relative mb-3 flex flex-wrap items-center justify-between gap-2.5 rounded-lg border border-subtle bg-surface-1/90 px-3 py-2 text-foreground shadow-sm backdrop-blur min-w-0 max-w-full overflow-hidden"
    >
      {/* Left side: Live Pulse Status & Alert Detail */}
      <div className="flex min-w-0 flex-1 items-center gap-2.5">
        {/* Live Radar Pulse */}
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="relative flex h-2.5 w-2.5">
            {active && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            )}
            <span
              className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                active ? "bg-emerald-500" : "bg-muted-foreground/50"
              }`}
            />
          </span>
          <span className="hidden sm:inline text-mono ba-text-3xs font-bold uppercase tracking-wider text-muted-foreground">
            {active ? "LIVE INGEST" : "STREAM PAUSED"}
          </span>
        </div>

        <span className="hidden sm:inline h-3.5 w-px bg-border/60 shrink-0" />

        {/* Latest Alert Item */}
        {latestAlert ? (
          <div className="flex min-w-0 flex-1 items-center gap-2">
            {/* Vendor chip */}
            <span
              className={`hidden md:inline-flex shrink-0 items-center rounded border px-1.5 py-0.2 text-mono ba-text-3xs font-semibold ${vendor.color} ${vendor.border}`}
            >
              {vendor.label}
            </span>

            {/* Severity Pill */}
            <span
              className={`shrink-0 rounded px-1.5 py-0.2 text-mono ba-text-3xs font-bold uppercase tracking-wider ${
                latestAlert.severity === "critical"
                  ? "bg-red-500/20 text-red-400 border border-red-500/40"
                  : latestAlert.severity === "high"
                  ? "bg-orange-500/20 text-orange-400 border border-orange-500/40"
                  : "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40"
              }`}
            >
              {latestAlert.severity}
            </span>

            {/* Title & Host/User */}
            <span className="truncate text-mono ba-text-2xs font-semibold text-foreground">
              {latestAlert.title}
            </span>

            {latestAlert.technique && (
              <span className="hidden lg:inline-flex shrink-0 rounded bg-surface-2 border border-subtle px-1 py-0.2 text-mono ba-text-3xs text-primary">
                {latestAlert.technique}
              </span>
            )}

            {latestAlert.host && (
              <span className="hidden xl:inline-flex shrink-0 text-mono ba-text-3xs text-muted-foreground">
                ({latestAlert.host})
              </span>
            )}
          </div>
        ) : (
          <div className="text-mono ba-text-2xs text-muted-foreground truncate">
            Awaiting incoming telemetry...
          </div>
        )}
      </div>

      {/* Right side: Action Buttons & Controls */}
      <div className="flex items-center gap-1.5 shrink-0">
        {/* Triage Pivot Button */}
        {latestAlert && (
          <button
            onClick={() => navigate({ to: "/triage" })}
            className="inline-flex h-6 items-center gap-1 rounded bg-primary/10 border border-primary/30 px-2 text-mono ba-text-3xs font-medium text-primary hover:bg-primary/20 transition-colors"
            title="Inspect in Autonomous Alert Triage Co-Pilot"
          >
            <span>Triage</span>
            <ArrowRight className="h-2.5 w-2.5" />
          </button>
        )}

        {/* Trigger Burst Menu */}
        <div className="relative">
          <button
            onClick={() => setScenarioOpen((v) => !v)}
            disabled={simulating}
            className="inline-flex h-6 items-center gap-1 rounded border border-subtle bg-surface-2 px-2 text-mono ba-text-3xs text-foreground hover:border-primary/40 hover:text-primary transition-colors disabled:opacity-50"
            title="Simulate Enterprise Attack Burst"
          >
            <Zap className="h-2.5 w-2.5 text-warning" />
            <span className="hidden sm:inline">Burst Ingest</span>
            <ChevronDown className="h-2.5 w-2.5" />
          </button>

          {scenarioOpen && (
            <div className="absolute right-0 top-7 z-50 w-52 rounded-lg border border-subtle bg-surface-0 p-1 shadow-xl text-left">
              <div className="px-2 py-1 text-mono ba-text-3xs text-muted-foreground font-semibold uppercase tracking-wider border-b border-subtle">
                Simulate Ingest Scenario
              </div>
              <button
                onClick={() => handleTriggerBurst("apt29")}
                className="w-full text-left rounded p-1.5 text-mono ba-text-2xs text-foreground hover:bg-surface-2 hover:text-primary transition-colors flex items-center justify-between"
              >
                <span>APT29 M365 AitM Phish</span>
                <span className="text-mono ba-text-3xs text-muted-foreground">3 alerts</span>
              </button>
              <button
                onClick={() => handleTriggerBurst("volt_typhoon")}
                className="w-full text-left rounded p-1.5 text-mono ba-text-2xs text-foreground hover:bg-surface-2 hover:text-primary transition-colors flex items-center justify-between"
              >
                <span>Volt Typhoon LOLBins</span>
                <span className="text-mono ba-text-3xs text-muted-foreground">3 alerts</span>
              </button>
              <button
                onClick={() => handleTriggerBurst("ransomware")}
                className="w-full text-left rounded p-1.5 text-mono ba-text-2xs text-foreground hover:bg-surface-2 hover:text-primary transition-colors flex items-center justify-between"
              >
                <span>BlackCat Ransomware</span>
                <span className="text-mono ba-text-3xs text-muted-foreground">3 alerts</span>
              </button>
            </div>
          )}
        </div>

        {/* Audio Mute / Unmute */}
        <button
          onClick={handleToggleMute}
          className="inline-flex h-6 w-6 items-center justify-center rounded border border-subtle bg-surface-2 text-muted-foreground hover:border-primary/40 hover:text-foreground transition-colors"
          title={muted ? "Unmute alert tones" : "Mute alert tones"}
          aria-label={muted ? "Unmute alert tones" : "Mute alert tones"}
        >
          {muted ? <VolumeX className="h-3 w-3" /> : <Volume2 className="h-3 w-3 text-emerald-400" />}
        </button>

        {/* Stream Play / Pause */}
        <button
          onClick={handleToggleStream}
          className="inline-flex h-6 w-6 items-center justify-center rounded border border-subtle bg-surface-2 text-muted-foreground hover:border-primary/40 hover:text-foreground transition-colors"
          title={active ? "Pause live stream" : "Resume live stream"}
          aria-label={active ? "Pause live stream" : "Resume live stream"}
        >
          {active ? <Pause className="h-3 w-3 text-warning" /> : <Play className="h-3 w-3 fill-current text-primary" />}
        </button>
      </div>
    </div>
  );
}

import { SiemSimulationRunner } from "@/components/detection/SiemSimulationRunner";
import { SiemQueryTranslatorPanel } from "@/components/detection/SiemQueryTranslatorPanel";
import { DetectionRuleOptimizer } from "@/components/detection/DetectionRuleOptimizer";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState, useRef } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, SendToRow, Chip, IocInventory } from "@/components/soc";
import { EntityHeader, EntitySection, MetricGrid, HeaderAction } from "@/components/entity";
import { KeyFields, EvidenceCard, TwoColumnOutput, VerdictBanner, Empty } from "@/components/output";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { ShieldAlert, Copy, ArrowRight, ArrowLeftRight, Database, Play, Sparkles, Crosshair, Check, RotateCcw, Download, Upload, Hash, ShieldCheck, TriangleAlert as AlertTriangle, Loader2, Plus, FileCode as FileCode2, Wand2, Search, BookMarked, Trash2, Edit3, Save, X, ListFilter, Info, Library, Target, FlaskConical, Activity, CheckCircle2, Rocket, PencilLine, RefreshCw, Archive, FilePlus2, Gauge, Pin } from "lucide-react";
import { mapMitre, generateSigmaRule, getIdsRuleTemplates, buildIdsRule } from "@/api/detection";
import { translateSigma, listSigmaBackends } from "../api/detection";
import { type Severity } from "@/lib/severity";
import { sendToCase } from "@/lib/handoff";
import { useLocker } from "@/lib/locker";
import { pushTimelineEvent } from "@/lib/timeline";
import { copyText } from "@/lib/copy";
import { notify } from "@/lib/notify";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { type Format, type MitreResult, type MitreMatch, type GenResult, type SavedRule, type DetectionState,
  FMT_ICONS, autoDetectFmt, TEMPLATES, highlight, extractIocs, genReport,
  loadRules, saveRules, normalizeRule, genId, validateRule, analyzeRule, slugRuleKey, ruleFromSignal, type RuleSignalSource,
  canTransition, transitionRule, STATE_TONE, detectionNodeId, simulationNodeId, deploymentNodeId,
  runCorpus, corpusDigest, SIM_CORPUS, type CorpusRun, ruleCategory, RULE_CATEGORIES, type RuleCategory,
  computeMitreCoverage, CONVERSION_PARITY, type ParityCell } from "@/data/detection";
import { addEdge, getAllEdges, eventDigest } from "@/lib/provenance";
import { loadCases } from "@/data/case";
import { loadPins, togglePinned } from "@/lib/pins";
import { ALL_TECHNIQUES } from "@/data/mitre";

export const Route = createFileRoute("/detection")({ component: DetectionPage });

function DetectionPage() {
  const navigate = useNavigate();
  const { filterText, setFilterText, showFilter, setShowFilter, toggleFilter } = useOutputFilter();
  const [hasRun, setHasRun] = useState(false);
  const [corpus, setCorpus] = useState<CorpusRun | null>(null);
  const [fmt, setFmt] = useState<Format>("sigma");
  const [rule, setRule] = useState("");
  const [event, setEvent] = useState("");
  const [copied, setCopied] = useState(false);

  const [mitreResults, setMitreResults] = useState<MitreResult | null>(null);
  const [mitreLoading, setMitreLoading] = useState(false);
  const [mitreError, setMitreError] = useState<string | null>(null);

  const [genDescription, setGenDescription] = useState("");
  const [genSeverity, setGenSeverity] = useState<Severity>("medium");
  const [genLoading, setGenLoading] = useState(false);
  const [genResult, setGenResult] = useState<GenResult | null>(null);
  const [genError, setGenError] = useState<string | null>(null);
  const locker = useLocker();

  /* ── IDS Rule Generator ── */
  const [idsTemplates, setIdsTemplates] = useState<Record<string, unknown> | null>(null);
  const [idsSelected, setIdsSelected] = useState<string | null>(null);
  const [idsEngine, setIdsEngine] = useState<"suricata" | "snort">("suricata");
  const [idsProtocol, setIdsProtocol] = useState("http");
  const [idsBuffer, setIdsBuffer] = useState<"http_uri" | "http_header" | "none">("http_uri");
  const [idsMsg, setIdsMsg] = useState("");
  const [idsContent, setIdsContent] = useState("");
  const [idsSid, setIdsSid] = useState("2000001");
  const [idsPriority, setIdsPriority] = useState("2");
  const [idsRule, setIdsRule] = useState<string | null>(null);
  const [idsBuildLoading, setIdsBuildLoading] = useState(false);
  const [idsCopied, setIdsCopied] = useState(false);
  const [idsShowPanel, setIdsShowPanel] = useState(false);

  /* ── Sigma → SIEM Translator ── */
  const [sigmaBackends, setSigmaBackends] = useState<{ id: string; label: string }[]>([]);
  const [sigmaTarget, setSigmaTarget] = useState("splunk");
  const [sigmaTransResult, setSigmaTransResult] = useState<{ target_label: string; queries: string[]; errors: string[] } | null>(null);
  const [sigmaTransLoading, setSigmaTransLoading] = useState(false);
  const [sigmaTransCopied, setSigmaTransCopied] = useState(false);

  useEffect(() => {
    listSigmaBackends().then((data) => { setSigmaBackends(data as any); }).catch(() => {});
  }, []);

  useEffect(() => {
    getIdsRuleTemplates()
      .then((data) => { setIdsTemplates(data as Record<string, unknown>); const keys = Object.keys(data as Record<string, unknown>); if (keys.length) setIdsSelected(keys[0]); })
      .catch(() => setIdsTemplates({}));
  }, []);

  useEffect(() => {
    if (idsTemplates && idsSelected) {
      const t = (idsTemplates[idsSelected] as any)?.data || {};
      setIdsMsg(t.msg || "");
      setIdsContent(t.content || "");
      setIdsSid(t.sid || "2000001");
      setIdsPriority(t.priority || "2");
      setIdsRule(null);
    }
  }, [idsTemplates, idsSelected]);

  const handleIdsBuild = async () => {
    if (!idsMsg && !idsContent) return;
    setIdsBuildLoading(true);
    setIdsRule(null);
    try {
      const res = await buildIdsRule({
        engine: idsEngine, action: "alert", protocol: idsProtocol,
        src_ip: "$EXTERNAL_NET", src_port: "any", direction: "->", dst_ip: "$HOME_NET", dst_port: "any",
        msg: idsMsg, content: idsContent, pcre: "", flow: "to_server,established",
        classtype: "trojan-activity", priority: idsPriority, sid: idsSid, rev: "1",
        extra_options: "", nocase: true,
        http_uri: idsBuffer === "http_uri",
        http_header: idsBuffer === "http_header",
      }) as any;
      setIdsRule(res.rule);
      setIdsShowPanel(true);
    } catch (e: any) {
      notify.error(e?.message || "IDS build failed", { description: e?.suggestion });
    } finally {
      setIdsBuildLoading(false);
    }
  };

  const handleSigmaTranslate = async () => {
    if (!rule.trim() || fmt !== "sigma") return;
    setSigmaTransLoading(true);
    setSigmaTransResult(null);
    try {
      const res = await translateSigma(rule, sigmaTarget) as any;
      setSigmaTransResult(res);
    } catch (e: any) {
      notify.error(e?.message || "Translation failed");
    } finally {
      setSigmaTransLoading(false);
    }
  };

  /* ── Rule library ── */
  const [showLib, setShowLib] = useState(false);
  const [showDash, setShowDash] = useState(false);
  const [savedRules, setSavedRules] = useState<SavedRule[]>(() => loadRules());
  const [libName, setLibName] = useState("");
  const [libTags, setLibTags] = useState("");
  const [, setLibNotice] = useState("");
  const [ruleSearch, setRuleSearch] = useState("");
  const [libCategory, setLibCategory] = useState<string>("infer");
  const [libFacet, setLibFacet] = useState<string>("all");
    const bundleInputRef = useRef<HTMLInputElement>(null);

  const handleExportBundle = () => {
    const bundle = {
      version: "1.0",
      exportedAt: new Date().toISOString(),
      generator: "BeyondLabs Detection Engineering Lab",
      rules: savedRules,
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `beyondlabs-detection-bundle-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    notify.success(`Exported ${savedRules.length} rules in Detection bundle`);
  };

  const handleImportBundle = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const parsed = JSON.parse(evt.target?.result as string);
        const incoming = Array.isArray(parsed) ? parsed : Array.isArray(parsed.rules) ? parsed.rules : [];
        if (!incoming.length) {
          notify.error("No valid rules found in bundle");
          return;
        }
        const normalized = incoming.map(normalizeRule);
        const merged = [...savedRules];
        let added = 0;
        for (const r of normalized) {
          if (!merged.some(m => m.id === r.id || (m.name === r.name && m.format === r.format))) {
            merged.push(r);
            added++;
          }
        }
        setSavedRules(merged);
        saveRules(merged);
        notify.success(`Imported ${added} new rule(s) into library`);
      } catch (err: any) {
        notify.error("Failed to parse rule bundle JSON: " + (err?.message || ""));
      }
    };
    reader.readAsText(file);
    if (bundleInputRef.current) bundleInputRef.current.value = "";
  };

  const [pinnedRuleIds, setPinnedRuleIds] = useState<string[]>(() => loadPins("detection"));
  const toggleRulePin = useCallback((id: string) => {
    setPinnedRuleIds(loadPins("detection"));
    togglePinned("detection", id);
    setPinnedRuleIds(loadPins("detection"));
  }, []);

  /* ── Validation & analysis ── */
  const [showAnalysis, setShowAnalysis] = useState(false);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setShowLib(false); setShowAnalysis(false); setIdsShowPanel(false); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const validation = useMemo(() => validateRule(rule, fmt), [rule, fmt]);
  const analysis = useMemo(() => analyzeRule(rule, fmt), [rule, fmt]);
  const hasErrors = validation.some(v => v.type === "error");
  const hasWarnings = validation.some(v => v.type === "warning");

  function parityTone(c: ParityCell): "success" | "warning" | "default" {
    return c === "yes" ? "success" : c === "partial" ? "warning" : "default";
  }

  const tpl = TEMPLATES[fmt];
  const result = useMemo(() => tpl.matcher(event), [tpl, event]);

  const switchFmt = (f: Format) => { setFmt(f); setRule(TEMPLATES[f].rule); setEvent(TEMPLATES[f].event); setMitreResults(null); setMitreError(null); setGenResult(null); setGenError(null); setShowLib(false); setCorpus(null); };
  const reset = () => { setRule(""); setEvent(""); setHasRun(false); setMitreResults(null); };

  const handleEvaluate = useCallback(async () => {
    if (mitreLoading) return;
    setHasRun(true);
    setMitreLoading(true);
    setMitreError(null);
    try {
      const text = [rule, event].filter(Boolean).join("\n");
      const res = await mapMitre(text);
      setMitreResults(res as MitreResult);
      pushTimelineEvent({ source: "detection", verb: "mapped", detail: `MITRE mapping for ${fmt} rule`, result: `${(res as MitreResult).matches?.length ?? 0} matches` });
    } catch (e: any) {
      setMitreError(e?.message || "MITRE mapping failed");
    } finally {
      setMitreLoading(false);
    }
  }, [rule, event, mitreLoading, fmt]);

  const handleGenerate = useCallback(async () => {
    if (genLoading || !genDescription.trim()) return;
    setGenLoading(true);
    setGenError(null);
    try {
      const res = await generateSigmaRule(
        `Generated: ${genDescription.slice(0, 60)}`,
        genDescription,
        genSeverity,
        "",
      );
      setGenResult(res);
      pushTimelineEvent({ source: "detection", verb: "generated", detail: `Generated ${fmt} rule: ${genDescription.slice(0, 60)}`, result: genSeverity });
    } catch (e: any) {
      setGenError(e?.message || "Rule generation failed");
    } finally {
      setGenLoading(false);
    }
  }, [genDescription, genSeverity, genLoading, fmt]);

  const loadGenerated = () => {
    if (genResult?.sigma_yaml) {
      setRule(genResult.sigma_yaml);
      setGenResult(null);
      setGenDescription("");
    }
  };

  const copy = () => { try { copyText(rule); } catch {/* noop */} setCopied(true); setTimeout(() => setCopied(false), 1200); };
  const clearMitre = () => setMitreResults(null);

  const ruleLines = rule.split("\n");
  const eventLines = event.split("\n");
  const iocs = useMemo(() => extractIocs(event), [event]);

  /* ── Library actions ── */
  const [activeRuleId, setActiveRuleId] = useState<string | null>(null);
  const activeRule = savedRules.find(r => r.id === activeRuleId) ?? null;

  const saveCurrent = () => {
    const name = libName.trim() || `Rule ${savedRules.length + 1}`;
    const tags = libTags.split(",").map(t => t.trim()).filter(Boolean);
    const existing = savedRules.findIndex(r => r.name === name && r.format === fmt);
    const prev = existing >= 0 ? savedRules[existing] : null;
    const id = prev?.id ?? genId();
    const entry: SavedRule = {
      id,
      name, format: fmt, rule, event,
      created: prev?.created ?? Date.now(), updated: Date.now(), tags,
      ruleKey: prev?.ruleKey ?? slugRuleKey(name, id),
      state: prev?.state ?? "draft",
      stateUpdated: prev?.stateUpdated ?? Date.now(),
      version: prev?.version ?? 0,
      technique: prev?.technique,
      category: libCategory === "infer" ? undefined : (libCategory as RuleCategory | undefined),
    };
    let next: SavedRule[];
    if (existing >= 0) { next = [...savedRules]; next[existing] = entry; }
    else next = [...savedRules, entry];
    setSavedRules(next);
    saveRules(next);
    setActiveRuleId(entry.id);
    setLibNotice(`Saved "${name}"`);
    pushTimelineEvent({ source: "detection", verb: existing >= 0 ? "updated-rule" : "saved-rule", detail: `${existing >= 0 ? "Updated" : "Saved"} ${fmt} rule: ${name}`, result: `${tags.length} tags` });
    setTimeout(() => setLibNotice(""), 2000);
  };
  const loadRule = (r: SavedRule) => {
    setFmt(r.format);
    setRule(r.rule);
    setEvent(r.event);
    setActiveRuleId(r.id);
    setHasRun(false);
    setMitreResults(null);
    setShowLib(false);
  };

  // Check for pending rule promoted from SIEM Hunting Arsenal
  useEffect(() => {
    try {
      const pendingId = localStorage.getItem("ba.detection.pendingRuleId");
      if (pendingId) {
        const rules = loadRules();
        const found = rules.find((r) => r.id === pendingId);
        if (found) {
          loadRule(found);
          notify.success(`Loaded tuned Sigma rule "${found.name}" into sandbox`);
        }
        localStorage.removeItem("ba.detection.pendingRuleId");
      }
    } catch {
      // noop
    }
  }, []);

  const deleteRule = (id: string) => {
    const next = savedRules.filter(r => r.id !== id);
    setSavedRules(next);
    saveRules(next);
    if (activeRuleId === id) setActiveRuleId(null);
  };
  const duplicateRule = (r: SavedRule) => {
    const entry: SavedRule = { ...r, id: genId(), name: `${r.name} (copy)`, ruleKey: slugRuleKey(`${r.name} (copy)`, genId()), state: "draft", stateUpdated: Date.now(), version: 0, created: Date.now(), updated: Date.now() };
    const next = [...savedRules, entry];
    setSavedRules(next);
    saveRules(next);
    loadRule(entry);
  };

  /* ── create rule from signal (§5 drives) ── */
  const [createSrc, setCreateSrc] = useState<RuleSignalSource["kind"]>("finding");
  const [createFindingId, setCreateFindingId] = useState("");
  const [createTech, setCreateTech] = useState("");
  const [createIoc, setCreateIoc] = useState("");
  const findingsAcross = useMemo(() => {
    const out: { caseId: string; caseTitle: string; findingId: string; finding: { title: string; severity: Severity; technique?: string; iocs?: { value: string }[] } }[] = [];
    for (const c of loadCases()) {
      for (const f of c.findings ?? []) {
        out.push({ caseId: c.id, caseTitle: c.title, findingId: f.id, finding: f });
      }
    }
    return out;
  }, []);

  const createRuleFromSignal = () => {
    let src: RuleSignalSource | null = null;
    if (createSrc === "finding") {
      const hit = findingsAcross.find((x) => x.findingId === createFindingId);
      if (!hit) { notify.error("Select a finding from a loaded case"); return; }
      src = { kind: "finding", label: `${hit.caseTitle} · ${hit.finding.title}`, iocs: hit.finding.iocs?.map((i) => i.value), severity: hit.finding.severity, technique: hit.finding.technique };
    } else if (createSrc === "technique") {
      const t = ALL_TECHNIQUES.find((x) => x.id === createTech);
      if (!t) { notify.error("Select a MITRE technique"); return; }
      src = { kind: "technique", id: t.id, name: t.name, tactic: t.tactic };
    } else {
      if (!createIoc.trim()) { notify.error("Enter an IOC value"); return; }
      src = { kind: "ioc", value: createIoc.trim(), type: "unknown" };
    }
    const built = ruleFromSignal(src);
    const id = genId();
    const entry: SavedRule = {
      id, name: built.name, format: "sigma", rule: built.rule, event: "",
      created: Date.now(), updated: Date.now(),
      tags: built.tags,
      ruleKey: slugRuleKey(built.name, id),
      state: "draft", stateUpdated: Date.now(), version: 0,
      technique: built.technique,
    };
    const next = [...savedRules, entry];
    setSavedRules(next);
    saveRules(next);
    setActiveRuleId(entry.id);
    setFmt("sigma");
    setRule(built.rule);
    setEvent("");
    setHasRun(false);
    if (built.technique) {
      addEdge({ relation: "drives", from: { kind: "mitre", id: built.technique }, to: { kind: "detection", id: detectionNodeId(entry.ruleKey) }, source: "detection-editor", reason: `rule created from ${src.kind} signal: ${built.name.slice(0, 48)}` });
    }
    pushTimelineEvent({ source: "detection", verb: "saved-rule", detail: `Rule scaffolded from ${src.kind}: ${built.name}`, result: built.technique ? `drives ${built.technique}` : "draft" });
    notify.success(`Created rule from ${src.kind}${built.technique ? ` · drives ${built.technique}` : ""}`);
    setShowLib(false);
  };

  /* ── lifecycle transitions (§4) ── */
  const applyTransitionInternal = (to: DetectionState) => {
    const rule = activeRule;
    if (!rule) return;
    const next = transitionRule(rule, to);
    if (!next) return;
    const list = savedRules.map(r => r.id === rule.id ? next : r);
    setSavedRules(list);
    saveRules(list);
    pushTimelineEvent({ source: "detection", verb: "lifecycle", detail: `${rule.name}: ${rule.state} → ${to}`, result: to });
  };

  /** draft → validated: validation pass (0 errors) writes simulation node + validates edge. */
  const handleValidate = () => {
    const rule = activeRule;
    if (!rule) { notify.error("Save the rule first, then validate"); return; }
    if (hasErrors) { notify.error("Validation failed — fix errors before promoting"); return; }
    const detId = detectionNodeId(rule.ruleKey);
    const simId = simulationNodeId(rule.id, eventDigest(rule.event));
    addEdge({ relation: "validates", from: { kind: "detection", id: detId }, to: { kind: "simulation", id: simId }, source: "detection-editor", confidence: hasWarnings ? 0.6 : 0.9, reason: `validation pass (${validation.length} msgs, ${result.hit ? "match" : "no match"})` });
    pushTimelineEvent({ source: "detection", verb: "validated", detail: `${rule.name}: validation pass`, result: `${validation.length} msgs` });
    applyTransitionInternal("validated");
  };

  /** Corpus simulation: record matches/misses/FPs as a simulation node + validates edge. */
  const recordCorpusSimulation = () => {
    const rule = activeRule;
    if (!rule || !corpus) return;
    const simId = simulationNodeId(rule.id, eventDigest(corpusDigest(corpus)));
    const s = corpus.summary;
    addEdge({ relation: "validates", from: { kind: "detection", id: detectionNodeId(rule.ruleKey) }, to: { kind: "simulation", id: simId }, source: "detection-corpus", confidence: s.precision >= 0.75 && s.coverage >= 0.75 ? 0.9 : 0.5, reason: `corpus run (${s.matches} matches, ${s.misses} misses, ${s.falsePositives} FPs · coverage ${Math.round(s.coverage * 100)}%)` });
    pushTimelineEvent({ source: "detection", verb: "simulated", detail: `${rule.name}: corpus simulation recorded`, result: `${s.matches} matches · ${s.misses} misses · ${s.falsePositives} FPs · ${Math.round(s.coverage * 100)}% coverage` });
    notify.success(`Recorded corpus simulation for ${rule.name}`);
  };

  const handleApprove = () => applyTransitionInternal("approved");
  const handleDeploy = () => {
    const rule = activeRule;
    if (!rule) return;
    const depId = deploymentNodeId(rule.id, rule.version + 1);
    const sims = getAllEdges().filter(e => e.relation === "validates" && e.from.kind === "detection" && e.from.id === detectionNodeId(rule.ruleKey));
    const simId = sims.length ? sims[sims.length - 1].to.id : simulationNodeId(rule.id, eventDigest(rule.event));
    addEdge({ relation: "deploys", from: { kind: "simulation", id: simId }, to: { kind: "deployment", id: depId }, source: "deploy", reason: `deploy v${rule.version + 1}` });
    const next = transitionRule(rule, "deployed");
    if (!next) { notify.error("Only approved rules can deploy"); return; }
    const bumped = { ...next, version: rule.version + 1 };
    const list = savedRules.map(r => r.id === rule.id ? bumped : r);
    setSavedRules(list);
    saveRules(list);
    pushTimelineEvent({ source: "detection", verb: "deployed", detail: `${rule.name}: deployed v${bumped.version}`, result: depId });
    notify.success(`Deployed ${rule.name} v${bumped.version}`);
  };
  const handleRollback = () => {
    const rule = activeRule;
    if (!rule) return;
    const depId = deploymentNodeId(rule.id, rule.version + 1);
    const sims = getAllEdges().filter(e => e.relation === "validates" && e.from.kind === "detection" && e.from.id === detectionNodeId(rule.ruleKey));
    const simId = sims.length ? sims[sims.length - 1].to.id : simulationNodeId(rule.id, eventDigest(rule.event));
    addEdge({ relation: "deploys", from: { kind: "simulation", id: simId }, to: { kind: "deployment", id: depId }, source: "rollback", reason: `rollback v${rule.version + 1}` });
    const next = transitionRule(rule, "draft");
    if (!next) return;
    const bumped = { ...next, version: rule.version + 1 };
    const list = savedRules.map(r => r.id === rule.id ? bumped : r);
    setSavedRules(list);
    saveRules(list);
    pushTimelineEvent({ source: "detection", verb: "rolled-back", detail: `${rule.name}: rolled back v${rule.version + 1}`, result: "draft" });
  };
  const handleRetire = () => applyTransitionInternal("retired");
  const handleRevise = () => applyTransitionInternal("draft");

  const deployments = useMemo(() => {
    const rule = activeRule;
    if (!rule) return [];
    const detId = detectionNodeId(rule.ruleKey);
    const simIds = new Set(getAllEdges().filter(e => e.relation === "validates" && e.from.kind === "detection" && e.from.id === detId).map(e => e.to.id));
    return getAllEdges()
      .filter(e => e.relation === "deploys" && e.from.kind === "simulation" && simIds.has(e.from.id))
      .sort((a, b) => a.ts.localeCompare(b.ts));
  }, [activeRule]);

  /* ── Detection dashboard (Phase 2) ── */
  const dashFailures = useMemo(() =>
    savedRules
      .map((r) => ({ r, msgs: validateRule(r.rule, r.format) }))
      .filter(({ msgs }) => msgs.some((m) => m.type === "error"))
      .map(({ r, msgs }) => ({ r, n: msgs.filter((m) => m.type === "error").length })),
    [savedRules],
  );
  const dashSims = useMemo(() =>
    getAllEdges()
      .filter((e) => e.relation === "validates")
      .sort((a, b) => b.ts.localeCompare(a.ts)),
    [],
  );
  const dashAlerts = useMemo(() => getAllEdges().filter((e) => e.relation === "fires").length, []);
  const coverage = useMemo(() => computeMitreCoverage(savedRules, getAllEdges()), [savedRules]);
  const coverageGaps = useMemo(() => coverage.filter((c) => c.status === "gap"), [coverage]);

  const filteredSaved = (ruleSearch.trim()
    ? savedRules.filter(r => r.name.toLowerCase().includes(ruleSearch.toLowerCase()) || r.tags.some(t => t.toLowerCase().includes(ruleSearch.toLowerCase())) || r.rule.toLowerCase().includes(ruleSearch.toLowerCase()))
    : savedRules).filter(r => libFacet === "all" ? true : libFacet === "unfiled" ? ruleCategory(r) === undefined : ruleCategory(r) === libFacet);
  const fmtRules = filteredSaved.filter(r => r.format === fmt);
  const otherRules = filteredSaved.filter(r => r.format !== fmt);

  const refIcon = (f: Format) => { const Ic = FMT_ICONS[f]; return <Ic className="h-3 w-3" />; };

  return (
    <ErrorBoundary name="Detection">
    <PageShell
      eyebrow="detection / rule editor"
      title="Detection Editor"
      description="Compose Sigma · YARA · KQL detections, dry-run against events, map to MITRE ATT&CK, or generate Sigma rules from a description."
      crumbs={[{ label: "Detection" }]}
      jumps={[{ label: "SIEM", to: "/siem" }, { label: "Investigation", to: "/parser" }]}>
      <>
      <EntityHeader
        variant="case"
        actions={
          <div className="flex items-center gap-1.5">
            <HeaderAction onClick={copy} className={copied ? "border-success/40 text-success hover:border-success/50 hover:text-success" : ""}>
              {copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
            </HeaderAction>
            <HeaderAction onClick={() => { setRule(TEMPLATES[fmt].rule); setEvent(TEMPLATES[fmt].event); }} icon={<Download className="h-3 w-3" />}>sample</HeaderAction>
            <HeaderAction onClick={reset} icon={<RotateCcw className="h-3 w-3" />}>reset</HeaderAction>
          </div>
        }
      >
        <div className="mt-3 grid gap-2 grid-cols-2 lg:grid-cols-4">
          {(["sigma", "yara", "kql", "suricata"] as Format[]).map((f) => {
            const active = fmt === f;
            const desc = f === "sigma" ? "Vendor-neutral log rule" : f === "yara" ? "File / memory signature" : f === "kql" ? "Defender / Azure query" : "Network IDS / Suricata";
            return (
              <button
                key={f}
                onClick={() => switchFmt(f)}
                className={
                  "group relative flex items-center justify-between gap-3 overflow-hidden rounded-md border px-3 py-2 text-left transition-all " +
                  (active ? "border-primary/60 bg-primary/10" : "border-subtle bg-surface-1 hover:border-primary/30 hover:bg-surface-2/70")
                }
              >
                <div className="flex items-center gap-2.5">
                  <span className={"grid h-7 w-7 place-items-center rounded border " + (active ? "border-primary/60 bg-primary/20 text-primary" : "border-divider-strong bg-surface-0 text-muted-foreground")}>
                    {refIcon(f)}
                  </span>
                  <div>
                    <div className={"text-mono ba-text-sm " + (active ? "text-primary" : "text-foreground")}>{f}</div>
                    <div className="ba-text-2xs text-muted-foreground">{desc}</div>
                  </div>
                </div>
                {active && <Chip tone="primary">active</Chip>}
              </button>
            );
          })}
          {fmt === "sigma" && (
            <button
              onClick={() => setGenResult(genResult ? null : { _show: true })}
              className="group relative flex items-center justify-between gap-3 overflow-hidden rounded-md border border-dashed border-primary/40 px-3 py-2 text-left transition-all hover:border-primary/60 hover:bg-primary/5"
            >
              <div className="flex items-center gap-2.5">
                <span className="grid h-7 w-7 place-items-center rounded border border-primary/40 bg-primary/10 text-primary">
                  <Wand2 className="h-3.5 w-3.5" strokeWidth={2.25} />
                </span>
                <div>
                  <div className="text-mono ba-text-sm text-primary">generate</div>
                  <div className="ba-text-2xs text-muted-foreground">Sigma from description</div>
                </div>
              </div>
            </button>
          )}
        </div>
      </EntityHeader>

      <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-subtle bg-surface-0 px-3 py-2.5">
        <button
          onClick={() => document.getElementById("detection-editor")?.focus()}
          className="inline-flex h-7 items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
        >
          <Plus className="h-3 w-3" /> new rule
        </button>
        <button onClick={() => setShowLib(s => !s)} className="inline-flex h-7 items-center gap-1.5 rounded border border-subtle px-2.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:text-foreground">
          <Library className="h-3 w-3" /> rule library
        </button>
        <button onClick={() => navigate({ to: "/mitre" })} className="inline-flex h-7 items-center gap-1.5 rounded border border-subtle px-2.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:text-foreground">
          <Target className="h-3 w-3" /> mitre
        </button>
        <button onClick={() => navigate({ to: "/sigma-tester" })} className="inline-flex h-7 items-center gap-1.5 rounded border border-subtle px-2.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:text-foreground">
          <FlaskConical className="h-3 w-3" /> sigma tester
        </button>
        {savedRules.length > 0 && (
          <span className="mx-1 hidden h-4 w-px bg-divider sm:block" />
        )}
        {savedRules.slice(-3).reverse().map((r) => (
          <button
            key={r.id}
            onClick={() => setShowLib(true)}
            className="hidden max-w-40 truncate rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary sm:inline-block"
            title={`Load "${r.name}" from the rule library`}
          >
            {r.name}
          </button>
        ))}
      </div>

      <SectionBar id="IN" label="Intake · format & rule body" meta={`${ruleLines.length} lines · ${rule.length} chars`} />

      {/* Sigma generate section */}
      {fmt === "sigma" && genResult && genResult._show && (
        <EntitySection title="Sigma generator" icon={Wand2} meta="LLM-powered rule generation">
          {!genResult.sigma_yaml ? (
            <div className="space-y-3">
              <label className="flex flex-col gap-1 text-mono ba-text-2xs text-muted-foreground">
                attack description
                <textarea
                  value={genDescription}
                  onChange={(e) => setGenDescription(e.target.value)}
                  rows={3}
                  placeholder="e.g. PowerShell launching encoded command from可疑 IP..."
                  className="rounded border border-subtle bg-surface-0 px-2 py-1.5 text-mono ba-text-base text-foreground placeholder:text-muted-foreground"
                />
              </label>
              <div className="flex items-end gap-2">
                <label className="flex flex-col gap-1 text-mono ba-text-2xs text-muted-foreground">
                  severity
                  <select
                    value={genSeverity}
                    onChange={(e) => setGenSeverity(e.target.value as Severity)}
                    className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-base text-foreground"
                  >
                    <option value="info">info</option>
                    <option value="low">low</option>
                    <option value="medium">medium</option>
                    <option value="high">high</option>
                    <option value="critical">critical</option>
                  </select>
                </label>
                <button
                  onClick={handleGenerate}
                  disabled={genLoading || !genDescription.trim()}
                  className="inline-flex h-8 items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 text-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:opacity-40"
                >
                  {genLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
                  {genLoading ? "generating..." : "generate"}
                </button>
              </div>
              {genError && <p className="text-mono ba-text-sm text-destructive">{genError}</p>}
            </div>
            ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <pre className="max-h-60 flex-1 overflow-auto rounded border border-subtle bg-surface-0 p-3 text-mono ba-text-sm leading-relaxed text-foreground">{genResult.sigma_yaml}</pre>
                {genResult.sigma_yaml && (
                  <button onClick={loadGenerated} className="shrink-0 self-start rounded border border-primary/50 bg-primary/10 px-2 py-1 font-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors duration-150">
                    <Plus className="h-3 w-3" /> load into editor
                  </button>
                )}
              </div>
              {genResult.mitre_mapping?.matches && genResult.mitre_mapping.matches.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {genResult.mitre_mapping.matches.map((m: MitreMatch) => (
                    <Chip key={m.technique_id} tone="warning">{m.technique_id} — {m.technique}</Chip>
                  ))}
                </div>
              )}
            </div>
          )}
        </EntitySection>
      )}

      {/* Rule library button + panel */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <button onClick={() => setShowLib(s => !s)} className={"inline-flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-mono ba-text-2xs transition-colors duration-150" + (showLib ? "border-primary/50 bg-primary/10 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}>
          <BookMarked className="h-3 w-3" />
          rule library
          {savedRules.length > 0 && <Chip tone={showLib ? "primary" : "default"}>{savedRules.length}</Chip>}
        </button>
        <button onClick={() => setShowDash(s => !s)} className={"inline-flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-mono ba-text-2xs transition-colors duration-150" + (showDash ? "border-primary/50 bg-primary/10 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}>
          <Gauge className="h-3 w-3" />
          dashboard
          {dashSims.length + dashFailures.length > 0 && <Chip tone={showDash ? "primary" : "default"}>{dashSims.length + dashFailures.length}</Chip>}
        </button>
      </div>

      {/* Detection dashboard panel (Phase 2) */}
      {showDash && (
        <EntitySection title="Detection dashboard" icon={Gauge} meta={`${savedRules.length} rules · ${dashSims.length} simulations · ${coverage.length} techniques`}>
          <MetricGrid
            metrics={[
              { label: "Draft rules", value: savedRules.filter(r => r.state === "draft").length, tone: "default" },
              { label: "Deployed rules", value: savedRules.filter(r => r.state === "deployed").length, tone: "primary" },
              { label: "Validation failures", value: dashFailures.length, tone: dashFailures.length > 0 ? "destructive" : "default" },
              { label: "Simulations", value: dashSims.length, tone: "info" },
              { label: "Recent alerts", value: dashAlerts, tone: dashAlerts > 0 ? "warning" : "default" },
            ]}
          />

          {/* MITRE coverage — Technique → Rules → Deployment, gaps highlighted */}
          <div className="mt-3">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-mono ba-text-2xs text-muted-foreground">MITRE coverage · from rule library + findings</span>
              <span className="text-mono ba-text-3xs text-muted-foreground">
                {coverage.filter((c) => c.status === "full").length} full · {coverage.filter((c) => c.status === "partial").length} partial · {coverageGaps.length} gaps
              </span>
            </div>
            {coverage.length === 0 ? (
              <p className="text-mono ba-text-2xs text-muted-foreground/70">
                No techniques mapped yet — create a rule from a finding/technique, or map findings to MITRE, and coverage appears here.
              </p>
            ) : (
              <div className="space-y-1">
                {coverage.map((c) => (
                  <div key={c.id} className="flex items-center justify-between gap-2 rounded border border-subtle bg-background/30 px-2 py-1">
                    <div className="flex min-w-0 flex-1 items-center gap-2">
                      <span className="shrink-0 text-mono ba-text-sm font-semibold text-foreground">{c.id}</span>
                      <span className="truncate text-mono ba-text-2xs text-fg-dim" title={c.name}>{c.name}</span>
                      {c.tactic && <Chip tone="default">{c.tactic}</Chip>}
                      {c.findingMapped && c.status === "gap" && <Chip tone="warning">in findings</Chip>}
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="text-mono ba-text-3xs text-muted-foreground">{c.ruleCount} rule{c.ruleCount !== 1 ? "s" : ""} · {c.deployedCount} deployed</span>
                      <Chip tone={c.status === "full" ? "success" : c.status === "partial" ? "warning" : "destructive"}>{c.status}</Chip>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <div className="mb-1.5 text-mono ba-text-2xs text-muted-foreground">validation failures</div>
              {dashFailures.length === 0 ? (
                <p className="text-mono ba-text-2xs text-muted-foreground/70">No saved rule currently fails validation.</p>
              ) : (
                <div className="space-y-1">
                  {dashFailures.map(({ r, n }) => (
                    <div key={r.id} className="flex items-center justify-between gap-2 rounded border border-destructive/30 bg-destructive/5 px-2 py-1">
                      <span className="min-w-0 flex-1 truncate text-mono ba-text-sm text-foreground">{r.name}</span>
                      <span className="text-mono ba-text-3xs text-destructive">{n} errors</span>
                      <button onClick={() => loadRule(r)} className="rounded border border-subtle px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary">open</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div>
              <div className="mb-1.5 text-mono ba-text-2xs text-muted-foreground">recent simulations</div>
              {dashSims.length === 0 ? (
                <p className="text-mono ba-text-2xs text-muted-foreground/70">Validate a rule or run the sample corpus, then record it — simulations appear here.</p>
              ) : (
                <div className="space-y-1">
                  {dashSims.slice(0, 5).map((e, i) => (
                    <div key={`${e.ts}-${i}`} className="flex items-center justify-between gap-2 rounded border border-subtle bg-background/30 px-2 py-1">
                      <span className="min-w-0 flex-1 truncate text-mono ba-text-sm text-foreground" title={e.reason}>{e.reason}</span>
                      <span className="text-mono ba-text-3xs text-muted-foreground">{new Date(e.ts).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
          <p className="mt-2 text-mono ba-text-3xs italic text-muted-foreground/70">
            Recent alerts ({dashAlerts}) — alert ingestion writes <code>fires</code> edges as a future capability; none are recorded yet.
          </p>
        </EntitySection>
      )}

      {showLib && (
        <EntitySection title="Rule library" icon={BookMarked} meta={`${savedRules.length} saved · ${fmtRules.length} in ${fmt}`}>
          {/* Save current */}
          <div className="mb-4 flex flex-wrap items-center gap-2 rounded border border-divider-strong bg-background/30 p-2">
            <input
              value={libName}
              onChange={e => setLibName(e.target.value)}
              placeholder={`Rule name… (default: Rule ${savedRules.length + 1})`}
              className="min-w-0 flex-1 rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50"
            />
            <input
              value={libTags}
              onChange={e => setLibTags(e.target.value)}
              placeholder="tags (comma)"
              className="w-32 rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50"
            />
            <select
              value={libCategory}
              onChange={e => setLibCategory(e.target.value)}
              title="Library category — infer falls back to rule-text keyword detection"
              className="w-28 rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
            >
              <option value="infer">infer</option>
              {RULE_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <button onClick={saveCurrent} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors duration-150">
              <Save className="h-3 w-3" /> save current
            </button>
            <button onClick={handleExportBundle} title="Export all rules as JSON bundle" className="inline-flex items-center gap-1 rounded border border-border bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
              <Download className="h-3 w-3" /> export bundle
            </button>
            <input type="file" ref={bundleInputRef} accept=".json" onChange={handleImportBundle} className="hidden" />
            <button onClick={() => bundleInputRef.current?.click()} title="Import detection rule bundle" className="inline-flex items-center gap-1 rounded border border-border bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
              <Upload className="h-3 w-3" /> import bundle
            </button>
          </div>

          {/* Category facets */}
          <div className="mb-2 flex flex-wrap items-center gap-1.5 px-3 pt-1">
            <button
              onClick={() => setLibFacet("all")}
              className={"inline-flex items-center gap-1 rounded border px-2 py-0.5 text-mono ba-text-2xs transition-colors duration-150" + (libFacet === "all" ? "border-primary/50 bg-primary/10 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}
            >
              all <Chip tone={libFacet === "all" ? "primary" : "default"}>{savedRules.length}</Chip>
            </button>
            {RULE_CATEGORIES.map((c) => {
              const count = savedRules.filter(r => ruleCategory(r) === c).length;
              if (count === 0 && libFacet !== c) return <span key={c} className="px-1 py-0.5 text-mono ba-text-3xs text-muted-foreground/50">{c}</span>;
              return (
                <button
                  key={c}
                  onClick={() => setLibFacet(libFacet === c ? "all" : c)}
                  className={"inline-flex items-center gap-1 rounded border px-2 py-0.5 text-mono ba-text-2xs capitalize transition-colors duration-150" + (libFacet === c ? "border-primary/50 bg-primary/10 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}
                >
                  {c} <Chip tone={libFacet === c ? "primary" : "default"}>{count}</Chip>
                </button>
              );
            })}
            <button
              onClick={() => setLibFacet("unfiled")}
              className={"inline-flex items-center gap-1 rounded border px-2 py-0.5 text-mono ba-text-2xs transition-colors duration-150" + (libFacet === "unfiled" ? "border-primary/50 bg-primary/10 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}
            >
              unfiled <Chip tone={libFacet === "unfiled" ? "primary" : "default"}>{savedRules.filter(r => ruleCategory(r) === undefined).length}</Chip>
            </button>
          </div>

          <div className="relative px-3 pb-1 pt-1">
            <Search className="absolute left-4 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
            <input
              value={ruleSearch}
              onChange={e => setRuleSearch(e.target.value)}
              placeholder="search rules by name, tag, or content…"
              className="w-full rounded border border-subtle bg-surface-0 py-1 pl-6 pr-2 text-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/40"
            />
          </div>
          {filteredSaved.length === 0 ? (
            <div className="px-3 pb-3">
              <Empty
                icon={Library}
                title={savedRules.length === 0 ? "No rules saved yet" : "No rules match your search"}
                hint={savedRules.length === 0 ? "Write a rule in the editor above and save it to start your detection library." : "Try a different search term or clear the search field."}
              />
            </div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-auto">
              {fmtRules.map(r => (
                <div key={r.id} className="flex items-center justify-between gap-2 rounded border border-subtle bg-background/30 px-3 py-2 hover:border-primary/30">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-mono ba-text-base font-semibold text-foreground">{r.name}</span>
                      {r.tags.map(t => <Chip key={t} tone="info">{t}</Chip>)}
                      {(() => { const c = ruleCategory(r); return c ? <Chip tone="primary">{c}</Chip> : null; })()}
                    </div>
                    <div className="mt-0.5 flex items-center gap-2 text-mono ba-text-2xs text-muted-foreground">
                      <span>{r.format}</span>
                      <span>· {r.rule.length} chars</span>
                      <span>· saved {new Date(r.updated).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => toggleRulePin(r.id)}
                      aria-label={pinnedRuleIds.includes(r.id) ? `Unpin "${r.name}"` : `Pin "${r.name}"`}
                      title={pinnedRuleIds.includes(r.id) ? "Unpin from dashboard" : "Pin to dashboard"}
                      className={"rounded border px-1.5 py-0.5 text-mono ba-text-2xs transition-colors duration-150 " + (pinnedRuleIds.includes(r.id) ? "border-primary/50 bg-primary/10 text-primary" : "border-subtle text-muted-foreground hover:text-primary")}
                    >
                      <Pin className={"inline h-3 w-3" + (pinnedRuleIds.includes(r.id) ? " fill-current" : "")} />
                    </button>
                    <button onClick={() => loadRule(r)} className="rounded border border-subtle px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-primary"><Edit3 className="inline h-3 w-3" /> load</button>
                    <button onClick={() => duplicateRule(r)} aria-label="Duplicate rule" className="rounded border border-subtle px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-primary"><Copy className="inline h-3 w-3" /></button>
                    <button onClick={() => deleteRule(r.id)} aria-label="Delete rule" className="rounded border border-subtle px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-destructive"><Trash2 className="inline h-3 w-3" /></button>
                  </div>
                </div>
              ))}
              {otherRules.length > 0 && (
                <details className="group">
                  <summary className="cursor-pointer px-1 pt-2 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                    other formats ({otherRules.length})
                  </summary>
                  <div className="mt-1 space-y-1">
                    {otherRules.map(r => (
                      <div key={r.id} className="flex items-center justify-between gap-2 rounded border border-divider-soft bg-background/20 px-2.5 py-1.5">
                        <div className="min-w-0 flex-1">
                          <span className="text-mono ba-text-sm text-fg-dim">{r.name}</span>
                          <span className="ml-2 text-mono ba-text-3xs text-muted-foreground">{r.format}</span>
                        </div>
                        <button onClick={() => loadRule(r)} aria-label="Load rule" className="rounded border border-subtle px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-primary"><Edit3 className="inline h-3 w-3" /></button>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          )}
        </EntitySection>
      )}

      {/* Create rule from signal (§5 drives) */}
      <SectionBar id="RF" label="Create rule · from finding / technique / IOC" meta={
        createSrc === "finding" ? `${findingsAcross.length} findings loaded` :
        createSrc === "technique" ? `${ALL_TECHNIQUES.length} techniques` : "free-form IOC"
      } />
      <Panel title="create from signal" icon={FilePlus2} meta={createSrc}>
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            {(["finding", "technique", "ioc"] as const).map((k) => (
              <button key={k} onClick={() => setCreateSrc(k)} className={"inline-flex items-center gap-1 rounded border px-2 py-1 text-mono ba-text-2xs transition-colors " + (createSrc === k ? "border-primary/50 bg-primary/10 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}>
                {k}
              </button>
            ))}
          </div>
          {createSrc === "finding" && (
            <select value={createFindingId} onChange={(e) => setCreateFindingId(e.target.value)} aria-label="Select finding" className="w-full rounded border border-divider-strong bg-surface-0 px-2 py-1 text-mono text-sm text-foreground outline-none focus:border-primary/50">
              <option value="">select a finding…</option>
              {findingsAcross.map((x) => (
                <option key={x.findingId} value={x.findingId}>{x.caseTitle}: {x.finding.title} ({x.finding.technique ?? "no technique"})</option>
              ))}
            </select>
          )}
          {createSrc === "technique" && (
            <select value={createTech} onChange={(e) => setCreateTech(e.target.value)} aria-label="Select technique" className="w-full rounded border border-divider-strong bg-surface-0 px-2 py-1 text-mono text-sm text-foreground outline-none focus:border-primary/50">
              <option value="">select a technique…</option>
              {ALL_TECHNIQUES.map((t) => (
                <option key={t.id} value={t.id}>{t.id} · {t.name} ({t.tactic})</option>
              ))}
            </select>
          )}
          {createSrc === "ioc" && (
            <input
              value={createIoc}
              onChange={(e) => setCreateIoc(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") createRuleFromSignal(); }}
              placeholder="e.g. 1.2.3.4, evil.com, sha256 hash…"
              className="w-full rounded border border-divider-strong bg-surface-0 px-2 py-1 text-mono text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50"
            />
          )}
          <div className="flex items-center gap-2">
            <button onClick={createRuleFromSignal} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-3 py-1 text-mono text-2xs text-primary hover:bg-primary/20">
              <FilePlus2 className="h-3 w-3" /> create draft rule
            </button>
            <span className="text-mono ba-text-xs text-muted-foreground">scaffolds a sigma rule; a `drives` edge links technique → this detection</span>
          </div>
        </div>
      </Panel>

      {/* Lifecycle panel (§4) — state machine + immutable deployment history */}
      <SectionBar id="LC" label="Lifecycle · state machine" meta={activeRule ? `${activeRule.state} · v${activeRule.version}` : "no active rule"} />
      <Panel
        title="lifecycle"
        icon={Activity}
        meta={activeRule ? `det-${activeRule.ruleKey.slice(0, 12)}…` : "—"}
        actions={activeRule ? <Chip tone={STATE_TONE[activeRule.state]}>{activeRule.state}</Chip> : <Chip tone="default">no active rule</Chip>}
      >
        {!activeRule ? (
          <Empty icon={Activity} title="No active rule" hint="Save or load a rule from the library above to start its lifecycle." />
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-1.5">
              {activeRule.state === "draft" && canTransition("draft", "validated") && (
                <button onClick={handleValidate} disabled={hasErrors} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:opacity-40" title="Requires 0 validation errors">
                  <Check className="h-3 w-3" /> validate
                </button>
              )}
              {canTransition(activeRule.state, "approved") && (
                <button onClick={handleApprove} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20">
                  <CheckCircle2 className="h-3 w-3" /> approve
                </button>
              )}
              {canTransition(activeRule.state, "deployed") && (
                <button onClick={handleDeploy} className="inline-flex items-center gap-1 rounded border border-success/50 bg-success/10 px-2 py-1 text-mono ba-text-2xs text-success hover:bg-success/20">
                  <Rocket className="h-3 w-3" /> deploy v{activeRule.version + 1}
                </button>
              )}
              {activeRule.state === "deployed" && (
                <button onClick={handleRollback} className="inline-flex items-center gap-1 rounded border border-warning/50 bg-warning/10 px-2 py-1 text-mono ba-text-2xs text-warning hover:bg-warning/20">
                  <RotateCcw className="h-3 w-3" /> rollback to draft
                </button>
              )}
              {canTransition(activeRule.state, "draft") && activeRule.state !== "deployed" && activeRule.state !== "retired" && (
                <button onClick={handleRevise} className="inline-flex items-center gap-1 rounded border border-subtle px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                  <PencilLine className="h-3 w-3" /> revise to draft
                </button>
              )}
              {activeRule.state === "retired" && (
                <button onClick={handleRevise} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20">
                  <RefreshCw className="h-3 w-3" /> reactivate (→ draft)
                </button>
              )}
              {canTransition(activeRule.state, "retired") && (
                <button onClick={handleRetire} className="inline-flex items-center gap-1 rounded border border-destructive/50 bg-destructive/10 px-2 py-1 text-mono ba-text-2xs text-destructive hover:bg-destructive/20">
                  <Archive className="h-3 w-3" /> retire
                </button>
              )}
              {activeRule.state === "draft" && canTransition("draft", "validated") && hasErrors && (
                <span className="text-mono ba-text-2xs text-muted-foreground">validate requires 0 errors</span>
              )}
            </div>

            {deployments.length > 0 && (
              <div className="space-y-1">
                <div className="text-mono ba-text-2xs text-muted-foreground">deployment history (immutable)</div>
                {deployments.map(d => (
                  <div key={d.id} className="flex items-center justify-between gap-2 rounded border border-divider-soft bg-background/20 px-2.5 py-1.5">
                    <div className="flex items-center gap-2">
                      <Chip tone={d.source === "rollback" ? "warning" : "success"}>{d.source}</Chip>
                      <span className="text-mono ba-text-2xs text-fg-dim">{d.reason}</span>
                    </div>
                    <span className="text-mono ba-text-3xs text-muted-foreground">{new Date(d.ts).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            )}

            <p className="text-mono ba-text-3xs text-muted-foreground">
              transitions are append-only: each deploy/rollback stamps a new deployment node; the current state is a projection of the event log.
            </p>
          </div>
        )}
      </Panel>

      <DetectionRuleOptimizer rule={rule} fmt={fmt} />

      <div className="grid gap-3 grid-cols-5">
        {/* Rule editor with line numbers + live syntax preview */}
        <Panel
          title={`rule · ${fmt}`}
          icon={FileCode2}
          meta={`${ruleLines.length} ln`}
          className="col-span-3"
          actions={
            <>
              {rule.trim() && (hasErrors || hasWarnings) && (
                <span className={"inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-mono ba-text-2xs " + (hasErrors ? "border-destructive/40 bg-destructive/10 text-destructive" : "border-warning/40 bg-warning/10 text-warning")}>
                  {hasErrors ? `${validation.filter(v => v.type === "error").length} err` : `${validation.filter(v => v.type === "warning").length} warn`}
                </span>
              )}
              <button onClick={() => setShowAnalysis(s => !s)} className={"inline-flex items-center gap-1 rounded border px-2 py-0.5 text-mono ba-text-2xs" + (showAnalysis ? "border-primary/50 bg-primary/10 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}>
                <Info className="h-3 w-3" /> analyze
              </button>
            </>
          }
        >
          <div className="relative grid grid-cols-[2.5rem_1fr] overflow-hidden rounded border border-divider-strong bg-surface-0">
            <div aria-hidden className="select-none border-r border-divider-soft bg-surface-1 py-2 text-right">
              {ruleLines.map((_, i) => (
                <div key={i} className="px-2 text-mono ba-text-2xs leading-[1.5] text-fg-dim">{i + 1}</div>
              ))}
            </div>
            <div className="relative">
              <pre
                aria-hidden
                className="pointer-events-none m-0 whitespace-pre-wrap break-words p-2 text-mono ba-text-base leading-[1.5] text-foreground"
                dangerouslySetInnerHTML={{ __html: highlight(rule, fmt, []) + "\n" }}
              />
              <textarea
                id="detection-editor"
                aria-label="Rule editor"
                value={rule}
                onChange={(e) => setRule(e.target.value)}
                onPaste={(e) => {
                  const text = e.clipboardData.getData("text");
                  const detected = autoDetectFmt(text);
                  if (detected && detected !== fmt) switchFmt(detected);
                }}
                spellCheck={false}
                className="absolute inset-0 resize-none overflow-hidden bg-transparent p-2 text-mono ba-text-base leading-[1.5] text-transparent caret-primary outline-none"
                style={{ WebkitTextFillColor: "transparent" }}
              />
            </div>
          </div>

          {/* Inline validation results */}
          {rule.trim() && (hasErrors || hasWarnings) && (
            <div className="mt-2 space-y-1">
              {validation.map((v, i) => (
                <div key={i} className={"flex items-start gap-2 rounded px-2 py-1 text-mono ba-text-2xs " + (v.type === "error" ? "bg-destructive/10 text-destructive" : "bg-warning/10 text-warning")}>
                  <span className="mt-0.5 shrink-0">{v.type === "error" ? <X className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}</span>
                  <span>{v.msg}{v.line != null ? ` (line ${v.line})` : ""}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Simulation pane */}
        <Panel
          title="simulate · event"
          icon={Sparkles}
          meta={`${eventLines.length} ln`}
          className="col-span-2"
          actions={<Chip tone={result.hit ? "destructive" : "default"}>{result.hit ? "MATCH" : "no match"}</Chip>}
        >
          <div className="relative overflow-hidden rounded border border-divider-strong bg-surface-0">
            <pre
              aria-hidden
              className="pointer-events-none m-0 max-h-40 whitespace-pre-wrap break-words p-2 text-mono ba-text-2xs leading-[1.5] text-foreground"
              dangerouslySetInnerHTML={{ __html: highlight(event, fmt, result.hits) + "\n" }}
            />
            <textarea
              aria-label="Simulated event"
              value={event}
              onChange={(e) => setEvent(e.target.value)}
              spellCheck={false}
              rows={Math.max(4, eventLines.length)}
              className="absolute inset-0 resize-none bg-transparent p-2 text-mono ba-text-2xs leading-[1.5] text-transparent caret-primary outline-none"
              style={{ WebkitTextFillColor: "transparent" }}
            />
          </div>

          <div className="mt-3 space-y-2">
            <div className="flex items-center justify-between text-mono ba-text-2xs text-muted-foreground">
              <span>token coverage</span>
              <span>{result.hits.length} / {tpl.matchTokens.length} conditions</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-border/40">
              <div
                className={"h-full transition-all " + (result.hit ? "bg-destructive" : "bg-warning")}
                style={{ width: `${Math.min(100, (result.hits.length / tpl.matchTokens.length) * 100)}%` }}
              />
            </div>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {(result.hits.length ? result.hits : ["—"]).map((h) => (
                <span key={h} className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 text-mono ba-text-2xs text-warning"><Crosshair className="h-2.5 w-2.5" /> {h}</span>
              ))}
            </div>
            <button
              onClick={handleEvaluate}
              disabled={mitreLoading}
              className="mt-1 inline-flex w-full items-center justify-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:opacity-40"
            >
              {mitreLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
              {mitreLoading ? "mapping..." : "evaluate"}
            </button>
          </div>
        </Panel>

        {/* Simulation corpus pane (Phase 2) */}
        <Panel
          title="simulate · corpus"
          icon={FlaskConical}
          meta={corpus ? `${SIM_CORPUS[fmt].length} samples · ${fmt}` : `${fmt} sample set`}
          className="col-span-2"
          actions={corpus && (
            <Chip tone={corpus.summary.falsePositives > 0 || corpus.summary.misses > 0 ? "warning" : "success"}>
              coverage {Math.round(corpus.summary.coverage * 100)}%
            </Chip>
          )}
        >
          <p className="mb-2 text-mono ba-text-2xs text-muted-foreground">
            Run the {fmt} keyword matcher against a fixed sample set — found / partial / benign / benign-with-keywords — and read deterministic match, miss, and false-positive counts.
          </p>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <button
              onClick={() => setCorpus(runCorpus(fmt))}
              className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-3 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors duration-150"
            >
              <Play className="h-3 w-3" />
              run corpus
            </button>
            <span className="text-mono ba-text-2xs text-muted-foreground">{SIM_CORPUS[fmt].length} samples · {fmt}</span>
          </div>

          {corpus && (
            <div className="space-y-3">
              <MetricGrid
                metrics={[
                  { label: "Matches", value: corpus.summary.matches, tone: "primary" },
                  { label: "Misses", value: corpus.summary.misses, tone: corpus.summary.misses > 0 ? "destructive" : "default" },
                  { label: "False positives", value: corpus.summary.falsePositives, tone: corpus.summary.falsePositives > 0 ? "warning" : "default" },
                  { label: "Coverage", value: `${Math.round(corpus.summary.coverage * 100)}%`, tone: corpus.summary.coverage >= 0.75 ? "primary" : "warning" },
                  { label: "Precision", value: `${Math.round(corpus.summary.precision * 100)}%`, tone: corpus.summary.precision >= 0.75 ? "primary" : "warning" },
                ]}
              />
              <div className="space-y-1.5">
                {corpus.samples.map((s) => (
                  <div key={s.id} className="flex items-center justify-between gap-2 rounded border border-subtle bg-background/30 px-2.5 py-1.5">
                    <div className="min-w-0 flex-1">
                      <span className="text-mono ba-text-sm text-foreground">{s.label}</span>
                      <span className="ml-2 text-mono ba-text-3xs text-muted-foreground">{s.expected}</span>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {s.hits.map((h) => <Chip key={h} tone="info">{h}</Chip>)}
                      <Chip tone={s.verdict === "tp" ? "primary" : s.verdict === "fp" ? "destructive" : s.verdict === "fn" ? "warning" : "default"}>
                        {s.verdict.toUpperCase()}
                      </Chip>
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={recordCorpusSimulation}
                  disabled={!activeRule}
                  title={!activeRule ? "Save a rule to record this simulation in provenance" : "Record matches/misses/FPs as a simulation node (validates)"}
                  className="inline-flex items-center gap-1 rounded border border-subtle px-2.5 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-primary disabled:opacity-40"
                >
                  <Library className="h-3 w-3" />
                  record simulation
                </button>
                {!activeRule && <span className="text-mono ba-text-2xs text-muted-foreground">save the rule above to record</span>}
              </div>
            </div>
          )}
        </Panel>
      </div>

            {/* High-Fidelity SIEM Telemetry Simulation Runner */}
      <div className="mb-3">
        <SiemSimulationRunner
          ruleContent={rule}
          format={fmt}
          onApplyTuningFilter={(filterSnippet) => {
            setRule((prev) => prev.trim() + "\n" + filterSnippet);
          }}
        />
      </div>

      {/* Multi-SIEM Query Transpiler for Sigma rules */}
      {fmt === "sigma" && rule.trim() && (
        <div className="mb-3">
          <SiemQueryTranslatorPanel
            sigmaYaml={rule}
            onPivotToSiem={(translatedQuery) => {
              navigate({ to: "/siem", search: { q: translatedQuery } as any });
            }}
          />
        </div>
      )}

      {/* Conversion parity reference — what survives Sigma ↔ KQL ↔ YARA conversion */}
      <Panel
        title="conversion parity · sigma ↔ kql ↔ yara"
        icon={ArrowLeftRight}
        storageKey="ba.panel.detection.parity"
        collapsible
        defaultCollapsed
        meta={`${CONVERSION_PARITY.length} constructs`}
      >
        <p className="mb-2 text-mono ba-text-2xs text-muted-foreground">
          Standard matrix for planning conversions — what each format can express and where meaning is lost.
          "partial" means expressible but lossy or requiring rewrites; this is a judgment about the formats, not any specific converter tool.
        </p>
        <div className="overflow-hidden rounded border border-divider-soft">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-divider-soft bg-surface-1 text-mono ba-text-2xs text-muted-foreground">
                <th className="px-2.5 py-1.5 text-left font-normal">construct</th>
                <th className="px-2 py-1.5 text-center font-normal">sigma</th>
                <th className="px-2 py-1.5 text-center font-normal">kql</th>
                <th className="px-2 py-1.5 text-center font-normal">yara</th>
                <th className="hidden px-2.5 py-1.5 text-left font-normal md:table-cell">note</th>
              </tr>
            </thead>
            <tbody>
              {CONVERSION_PARITY.map((row) => (
                <tr key={row.construct} className="border-b border-divider-soft last:border-b-0">
                  <td className="px-2.5 py-1.5 text-mono ba-text-xs text-foreground">{row.construct}</td>
                  {(["sigma", "kql", "yara"] as const).map((f) => (
                    <td key={f} className="px-2 py-1.5 text-center">
                      <Chip tone={parityTone(row[f] as ParityCell)}>{row[f] === "yes" ? "✓" : row[f] === "partial" ? "~" : "—"}</Chip>
                    </td>
                  ))}
                  <td className="hidden px-2.5 py-1.5 text-mono ba-text-2xs text-muted-foreground md:table-cell">{row.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Structural analysis panel */}
      {showAnalysis && analysis.length > 0 && (
        <EntitySection title={`Rule structure · ${fmt}`} icon={ListFilter} meta={`${analysis.length} fields`}>
          <div className="grid gap-1.5 grid-cols-3">
            {analysis.map((f) => (
              <div key={f.key} className="rounded border border-divider-soft bg-background/30 px-2.5 py-1.5">
                <div className="text-mono ba-text-3xs text-muted-foreground">{f.key}</div>
                <div className="mt-0.5 truncate text-mono ba-text-sm text-foreground" title={f.value}>{f.value}</div>
              </div>
            ))}
          </div>
        </EntitySection>
      )}

      <div className="flex items-center gap-2">
        <SectionBar id="OT" label="Output · verdict & mapping" meta={result.hit ? "rule would fire" : "rule does not match"} />
        {hasRun && (
          <button
            onClick={toggleFilter}
            className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono ba-text-2xs transition-colors duration-150" + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
            title="Toggle output filter"
          >
            <Search className="h-3 w-3" />
            filter
          </button>
        )}
      </div>

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
          onClose={() => { setShowFilter(false); setFilterText(""); }}
        />
      )}

      {!hasRun ? (
        <Empty icon={ShieldAlert} title="Ready to evaluate" hint="Click 'evaluate' in the simulate pane to run the rule against the event and map to MITRE ATT&CK." />
      ) : (
        <OutputFilter query={filterText.toLowerCase()}>
        <div className="space-y-5">
        <VerdictBanner
          verdict={result.hit ? "Rule matches event" : "No match"}
          tone={result.hit ? "warning" : "success"}
          icon={result.hit ? AlertTriangle : ShieldCheck}
          details={[
            result.hit ? `${result.hits.length} token(s): ${result.hits.join(", ")}` : "",
            `${fmt.toUpperCase()} · ${tpl.severity} severity`,
            mitreResults?.matches?.[0]?.technique_id || tpl.technique.id,
            mitreResults ? `${mitreResults.total_matches} technique(s) mapped` : "",
          ].filter(Boolean)}
        />

        {/* Metrics */}
        <MetricGrid
          metrics={[
            { label: "Format", value: fmt.toUpperCase(), tone: "primary" },
            { label: "Verdict", value: result.hit ? "MATCH" : "NO MATCH", tone: result.hit ? "destructive" : "default" },
            { label: "MITRE", value: mitreResults?.matches?.[0]?.technique_id || tpl.technique.id, tone: "warning" },
            { label: "Severity", value: tpl.severity, tone: tpl.severity === "critical" ? "destructive" : tpl.severity === "high" || tpl.severity === "medium" ? "warning" : tpl.severity === "low" ? "primary" : "default" },
            { label: "Tokens", value: result.hits.length },
            { label: "Platform", value: mitreResults?.matches?.[0]?.technique || tpl.technique.platform.split("/")[0] },
            { label: "Tactic", value: mitreResults?.matches?.[0]?.tactic || tpl.technique.tactic },
          ]}
        />

        {/* MITRE Mapping + Evidence side-by-side */}
        <TwoColumnOutput
          ratio="1:1"
          left={
            <EntitySection title="MITRE ATT&CK mapping" icon={Crosshair}>
              {mitreResults && (
                <div className="mb-2 flex justify-end">
                  <button onClick={clearMitre} className="inline-flex items-center gap-1 rounded border border-subtle px-2 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"><RotateCcw className="h-3 w-3" /> clear</button>
                </div>
              )}
              {mitreLoading ? (
                <div className="flex items-center gap-2 py-4 text-mono ba-text-sm text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> mapping to MITRE ATT&CK...
                </div>
              ) : mitreError ? (
                <p className="text-mono ba-text-sm text-destructive">{mitreError}</p>
              ) : mitreResults && mitreResults.matches && mitreResults.matches.length > 0 ? (
                <div className="space-y-3">
                  {mitreResults.matches.map((m: MitreMatch) => (
                    <div key={m.technique_id} className="rounded border border-subtle bg-background/30 p-2">
                      <div className="flex items-center justify-between">
                        <span className="text-mono ba-text-sm font-semibold text-foreground">{m.technique_id}</span>
                        <Chip tone={m.confidence === "high" ? "destructive" : m.confidence === "medium" ? "warning" : "default"}>{m.confidence}</Chip>
                      </div>
                      <p className="mt-0.5 ba-text-base text-foreground">{m.technique}</p>
                      <p className="ba-text-2xs text-muted-foreground">{m.tactic}</p>
                      {m.matched_keywords && m.matched_keywords.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {m.matched_keywords.map((kw: string) => (
                            <Chip key={kw} tone="info">{kw}</Chip>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                  {mitreResults.note && (
                    <p className="ba-text-2xs text-muted-foreground italic">{mitreResults.total_matches} technique(s) mapped · {mitreResults.note}</p>
                  )}
                </div>
              ) : (
                <p className="py-2 text-mono ba-text-sm text-muted-foreground">Click "evaluate" to map rule + event text against MITRE ATT&CK.</p>
              )}
            </EntitySection>
          }
          right={
            (result.hit && result.hits.length > 0) ? (
              <EvidenceCard severity={tpl.severity === "high" || tpl.severity === "critical" ? "warning" : "info"} title="Detection signal" reason={`${result.hits.length} token(s) matched in event: ${result.hits.join(", ")}`} action="Deploy rule to SIEM/EDR for validation against production traffic." limitation="Static matcher — no false-positive rate data available." />
            ) : (
              <EvidenceCard severity="info" title="No match" reason="Rule does not match the supplied event. Revise rule logic or check event format." action="Adjust detection selection or collect a more representative event sample." limitation="Static evaluation only." />
            )
          }
        />

        {/* IOCs in event */}
        <EntitySection title="IOCs in event" icon={Hash} meta={`${iocs.ips.length + iocs.urls.length + iocs.hashes.length} total`}>
          <KeyFields items={[
            { label: "IPs", value: iocs.ips.length ? iocs.ips.join(", ") : "—" },
            { label: "URLs", value: iocs.urls.length ? iocs.urls.join(", ") : "—" },
            { label: "Hashes", value: iocs.hashes.length ? iocs.hashes.join(", ") : "—" },
          ]} />
        </EntitySection>

        {/* IOC Inventory */}
        <EntitySection title="IOC Inventory" icon={Database} meta={`${iocs.ips.length + iocs.urls.length + iocs.hashes.length} indicators`}>
          <IocInventory groups={[
            { kind: "IPv4", items: iocs.ips, tone: "info" },
            { kind: "URL", items: iocs.urls, tone: "warning" },
            { kind: "Hash", items: iocs.hashes, tone: "warning" },
          ]} onSendTo={() => {}} />
          <div className="mt-2 flex flex-wrap gap-1.5">
            {iocs.ips.length > 0 && (
              <button onClick={() => { iocs.ips.forEach((v) => locker.add({ value: v, type: "ipv4", source: "/detection" })); notify.success(`Added ${iocs.ips.length} IPs to locker`); }}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:bg-surface-2/70 hover:text-foreground"
              >+ IPs ({iocs.ips.length})</button>
            )}
            {iocs.urls.length > 0 && (
              <button onClick={() => { iocs.urls.forEach((v) => locker.add({ value: v, type: "url", source: "/detection" })); notify.success(`Added ${iocs.urls.length} URLs to locker`); }}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:bg-surface-2/70 hover:text-foreground"
              >+ URLs ({iocs.urls.length})</button>
            )}
            {iocs.hashes.length > 0 && (
              <button onClick={() => { iocs.hashes.forEach((v) => locker.add({ value: v, type: v.length === 32 ? "md5" : v.length === 40 ? "sha1" : v.length === 64 ? "sha256" : "unknown", source: "/detection" })); notify.success(`Added ${iocs.hashes.length} hashes to locker`); }}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:bg-surface-2/70 hover:text-foreground"
              >+ Hashes ({iocs.hashes.length})</button>
            )}
          </div>
        </EntitySection>

        {/* Report */}
        <EntitySection title="Report (markdown)">
          <div className="mb-2 flex justify-end gap-1">
            <button onClick={() => { const md = genReport(tpl, result, rule); copyText(md); }} className="inline-flex items-center gap-1 rounded border border-subtle px-2 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"><Copy className="h-3 w-3" /> copy</button>
            <button onClick={() => { const md = genReport(tpl, result, rule); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `detection-${tpl.technique.id}-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-subtle px-2 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
          </div>
          <pre className="max-h-48 overflow-auto rounded bg-surface-0 p-3 text-mono ba-text-sm text-foreground">{genReport(tpl, result, rule)}</pre>
        </EntitySection>

          <div id="ids-engine">{/* IDS Rule Generator (from IdsBuilder essence) */}
          <EntitySection title="IDS Rule Generator & Workbench" icon={ShieldAlert} meta="Suricata & Snort Engine">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <span className="text-mono ba-text-2xs text-muted-foreground">engine</span>
                  <div className="flex rounded border border-divider-strong overflow-hidden text-mono ba-text-2xs">
                    <button
                      type="button"
                      onClick={() => setIdsEngine("suricata")}
                      className={"px-2.5 py-1 " + (idsEngine === "suricata" ? "bg-primary/20 text-primary font-bold" : "bg-surface-0 text-muted-foreground hover:text-foreground")}
                    >
                      Suricata
                    </button>
                    <button
                      type="button"
                      onClick={() => setIdsEngine("snort")}
                      className={"px-2.5 py-1 border-l border-divider-strong " + (idsEngine === "snort" ? "bg-primary/20 text-primary font-bold" : "bg-surface-0 text-muted-foreground hover:text-foreground")}
                    >
                      Snort
                    </button>
                  </div>
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="text-mono ba-text-2xs text-muted-foreground">protocol</span>
                  <select
                    value={idsProtocol}
                    onChange={(e) => setIdsProtocol(e.target.value)}
                    className="rounded border border-divider-strong bg-surface-0 px-2 py-1 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                  >
                    {["http", "tcp", "udp", "tls", "dns", "icmp"].map((p) => (
                      <option key={p} value={p}>{p.toUpperCase()}</option>
                    ))}
                  </select>
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="text-mono ba-text-2xs text-muted-foreground">buffer</span>
                  <select
                    value={idsBuffer}
                    onChange={(e) => setIdsBuffer(e.target.value as any)}
                    className="rounded border border-divider-strong bg-surface-0 px-2 py-1 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                  >
                    <option value="http_uri">http.uri (URI content)</option>
                    <option value="http_header">http.header (Header)</option>
                    <option value="none">raw payload (packet body)</option>
                  </select>
                </div>

                <div className="flex items-center gap-1.5 ml-auto">
                  <span className="text-mono ba-text-2xs text-muted-foreground">template</span>
                  <select
                    value={idsSelected || ""}
                    onChange={(e) => setIdsSelected(e.target.value)}
                    className="rounded border border-divider-strong bg-surface-0 px-2 py-1 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                  >
                    {idsTemplates && Object.keys(idsTemplates).map((k) => (
                      <option key={k} value={k}>{k}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid gap-2 grid-cols-1 sm:grid-cols-[1.5fr_2fr_90px_80px]">
                <input value={idsMsg} onChange={(e) => setIdsMsg(e.target.value)} placeholder="msg: Suspicious PowerShell URI" className="rounded border border-divider-strong bg-surface-0 px-2.5 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50" />
                <input value={idsContent} onChange={(e) => setIdsContent(e.target.value)} placeholder="content: .ps1 or /c2" className="rounded border border-divider-strong bg-surface-0 px-2.5 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50" />
                <input value={idsSid} onChange={(e) => setIdsSid(e.target.value)} placeholder="sid" className="rounded border border-divider-strong bg-surface-0 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50" />
                <select value={idsPriority} onChange={(e) => setIdsPriority(e.target.value)} className="rounded border border-divider-strong bg-surface-0 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50">
                  {["1","2","3","4"].map((p) => <option key={p} value={p}>prio {p}</option>)}
                </select>
              </div>

              <div className="flex items-center gap-2">
                <button onClick={handleIdsBuild} disabled={idsBuildLoading || (!idsMsg && !idsContent)} className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3.5 py-1.5 text-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:opacity-40 transition-colors duration-150">
                  {idsBuildLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
                  {idsBuildLoading ? "building..." : `generate ${idsEngine === "suricata" ? "Suricata" : "Snort"} rule`}
                </button>
                <button onClick={() => setIdsShowPanel(!idsShowPanel)} className="text-mono ba-text-2xs text-muted-foreground hover:text-foreground">{idsShowPanel ? "hide" : "show"} preview</button>
              </div>

              {idsShowPanel && idsRule && (
                <div className="rounded-lg border border-subtle bg-surface-0 p-3 space-y-2">
                  <pre className="overflow-x-auto text-mono ba-text-sm leading-relaxed text-foreground whitespace-pre-wrap">{idsRule}</pre>
                  <div className="flex items-center gap-2 pt-1 border-t border-subtle">
                    <button onClick={() => { copyText(idsRule); setIdsCopied(true); setTimeout(() => setIdsCopied(false), 1200); }} className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-2 px-2.5 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                      {idsCopied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy rule</>}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        switchFmt("suricata");
                        setRule(idsRule);
                        notify.success("Loaded rule into Suricata Sandbox Editor");
                        window.scrollTo({ top: 0, behavior: "smooth" });
                      }}
                      className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20"
                    >
                      <Rocket className="h-3 w-3" /> load into sandbox
                    </button>
                  </div>
                </div>
              )}
            </div>
          </EntitySection>
          </div>

          {/* Sigma → SIEM Translator */}
          {fmt === "sigma" && (
          <EntitySection title="Sigma → SIEM Translator" icon={Wand2} meta="pySigma">
            <div className="space-y-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-mono ba-text-2xs text-muted-foreground">target</span>
                <select
                  value={sigmaTarget}
                  onChange={(e) => setSigmaTarget(e.target.value)}
                  className="rounded border border-divider-strong bg-surface-0 px-2 py-1 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                >
                  {sigmaBackends.map((b) => (
                    <option key={b.id} value={b.id}>{b.label}</option>
                  ))}
                </select>
                <button
                  onClick={handleSigmaTranslate}
                  disabled={sigmaTransLoading || !rule.trim()}
                  className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-3 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:opacity-40"
                >
                  {sigmaTransLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
                  {sigmaTransLoading ? "translating..." : "translate"}
                </button>
              </div>
              {sigmaTransResult && (
                <div className="rounded border border-subtle bg-surface-0 p-3">
                  {sigmaTransResult.errors.length > 0 && (
                    <div className="mb-2 rounded border border-destructive/30 bg-destructive/5 p-2 text-mono ba-text-sm text-destructive">{sigmaTransResult.errors.join("; ")}</div>
                  )}
                  {sigmaTransResult.queries.length > 0 && (
                    <div className="space-y-2">
                      <div className="text-mono ba-text-2xs text-success">{sigmaTransResult.target_label}</div>
                      {sigmaTransResult.queries.map((q, i) => (
                        <div key={i} className="group relative rounded border border-subtle bg-surface-1 p-2.5">
                          <pre className="overflow-x-auto text-mono ba-text-sm leading-relaxed text-foreground whitespace-pre-wrap pr-8">{q}</pre>
                          <button
                            onClick={() => { copyText(q); setSigmaTransCopied(true); setTimeout(() => setSigmaTransCopied(false), 1200); }}
                            className="absolute right-1.5 top-1.5 rounded border border-subtle bg-surface-2 p-1 text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100"
                          >
                            {sigmaTransCopied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  {sigmaTransResult.queries.length === 0 && sigmaTransResult.errors.length === 0 && (
                    <p className="text-mono ba-text-sm text-muted-foreground">No output generated. Check the rule format.</p>
                  )}
                </div>
              )}
            </div>
          </EntitySection>
          )}

        <SendToRow targets={[
          { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
          { label: "SIEM Workspace", to: "/siem", icon: ShieldAlert },
          { label: "Case Notebook", to: "/case", icon: Database, onClick: () => sendToCase({ body: genReport(tpl, result, rule), source: "/detection", kind: "evidence" }) },
        ]} />


      </div>
      </OutputFilter>
      )}
      </>
    </PageShell>
    </ErrorBoundary>
  );
}

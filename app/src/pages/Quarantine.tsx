import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, Fingerprint, Lock, Pause, Play, Radio, Search, ShieldCheck, ShieldOff, Trash2, UserCheck, UserX, Wifi } from "lucide-react";
import { api } from "../api";
import type { QCandidate, QDevice, QResult, QSignal, QuarantineProbe } from "../types";
import { Banner, Button, Card, ConfirmDialog, EmptyState, Input, Modal, Pill, SegmentedControl, SkeletonRows, Toggle, useToast } from "../components/ui";
import { RollbackConfirmModal, useRollbackConfirm } from "../components/rollback";
import { fmtDate } from "../lib/format";

type Mode = "internet" | "nothing";

/**
 * The other approved address of the same Wi-Fi 7 device: private (locally
 * administered), one apart in the last byte, and the only such address
 * (never a guess between two). Access points may ask about either one.
 */
function pairPartner(d: QDevice, list: QDevice[]): QDevice | undefined {
  const local = (m: string) => (parseInt(m.slice(0, 2), 16) & 2) !== 0;
  if (d.mac.length !== 17 || !local(d.mac)) return undefined;
  const head = d.mac.slice(0, 15);
  const last = parseInt(d.mac.slice(15), 16);
  const found = list.filter((x) => x.mac !== d.mac && x.mac.length === 17 && local(x.mac) &&
    x.mac.slice(0, 15) === head && Math.abs(parseInt(x.mac.slice(15), 16) - last) === 1);
  return found.length === 1 ? found[0] : undefined;
}

/** A device's best label: the name given, the DHCP host name, the vendor. */
function useLabel() {
  const { t } = useTranslation();
  return (d: QDevice) =>
    d.name || d.hostname || (d.vendor ? t("quarantine.vendorDevice", { vendor: d.vendor }) : d.random ? t("quarantine.privateMac") : t("quarantine.unknownDevice"));
}

/**
 * Device quarantine: devices the router has not been told to trust get the
 * internet only (or nothing) in the protected zones, until approved.
 * Turning it on and changing zones run inside the rollback-confirm window.
 */
export function QuarantinePage() {
  const { t } = useTranslation();
  const { push } = useToast();
  const label = useLabel();
  const rc = useRollbackConfirm();
  const [probe, setProbe] = useState<QuarantineProbe>();
  const [you, setYou] = useState("");
  const [loadError, setLoadError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [zonesOpen, setZonesOpen] = useState(false);
  const [confirmOff, setConfirmOff] = useState(false);
  const [revoke, setRevoke] = useState<QDevice | null>(null);
  const [revokePair, setRevokePair] = useState(true);
  const [wifiConfirm, setWifiConfirm] = useState<"on" | "off" | null>(null);
  const [names, setNames] = useState<Record<string, string>>({});
  const [pauseMinutes, setPauseMinutes] = useState("30");
  const [now, setNow] = useState(() => Date.now() / 1000);

  const load = useCallback(async () => {
    try {
      const r = await api.quarantine();
      setProbe(r.state);
      setYou(r.you);
      setLoadError(false);
    } catch {
      setLoadError(true);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(() => { load(); setNow(Date.now() / 1000); }, 5000);
    return () => clearInterval(id);
  }, [load]);

  // Waiting addresses the router pairs up (one Wi-Fi 7 device seen with two
  // addresses at once) show as one row; both sides must name each other.
  const revokePartner = useMemo(() => {
    if (!revoke || !probe) return undefined;
    const p = pairPartner(revoke, probe.approved);
    return p && p.mac !== you ? p : undefined;
  }, [revoke, probe, you]);

  const pendingRows = useMemo(() => {
    const list = probe?.pending ?? [];
    const byMac = new Map(list.map((d) => [d.mac, d]));
    const shown = new Set<string>();
    const rows: { d: QDevice; twin?: QDevice }[] = [];
    for (const d of list) {
      if (shown.has(d.mac)) continue;
      const o = d.twin ? byMac.get(d.twin) : undefined;
      const twin = o && o.twin === d.mac && !shown.has(o.mac) ? o : undefined;
      shown.add(d.mac);
      if (twin) shown.add(twin.mac);
      // The lower address leads, so the row (and a name being typed in it)
      // stays put when the two swap places between refreshes.
      rows.push(twin && twin.mac < d.mac ? { d: twin, twin: d } : { d, twin });
    }
    return rows;
  }, [probe]);
  // A link from NetPulse names a device (#/quarantine?mac=…): a waiting one
  // is marked and scrolled to; an approved one is searched for below.
  const linked = useLinkedMac();
  useEffect(() => {
    if (!linked || !probe) return;
    const row = pendingRows.find(({ d, twin }) => d.mac === linked || twin?.mac === linked);
    if (row) document.getElementById(`q-pending-${row.d.mac}`)?.scrollIntoView({ block: "center" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linked, probe === undefined]);

  const run = useCallback(async (fn: () => Promise<QResult>, okText?: string) => {
    setBusy(true);
    try {
      const res = await fn();
      if (res.state) setProbe(res.state);
      if (res.confirm) rc.arm(res.confirm);
      if (okText) push({ tone: "ok", text: okText });
      return true;
    } catch (e) {
      push({ tone: "danger", text: t("quarantine.actionFailed"), detail: e instanceof Error ? e.message : String(e) });
      return false;
    } finally {
      setBusy(false);
      load();
    }
  }, [load, push, rc, t]);

  if (loadError && !probe) {
    return <Banner tone="danger" action={<Button size="sm" variant="secondary" onClick={load}>{t("common.retryNow")}</Button>}>{t("error.network")}</Banner>;
  }
  if (!probe) return <Card><SkeletonRows rows={4} /></Card>;

  const pauseActive = !!probe.pause.until && probe.pause.until > now;
  const protectedZones = probe.zones.filter((z) => z.protected).map((z) => z.name);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-h1">{t("quarantine.title")}</h1>
        <p className="text-small text-muted mt-1">{t("quarantine.subtitle")}</p>
      </div>

      {!probe.applicable && <Banner tone="warn">{t("quarantine.notApplicable", { reason: probe.reason ?? "" })}</Banner>}
      <Banner tone="info">{t("quarantine.scopeNote")}</Banner>

      {probe.applicable && !probe.enabled && (
        <Card>
          <EmptyState
            illustration={<ShieldCheck size={96} />}
            title={t("quarantine.offTitle")}
            body={t("quarantine.offBody")}
            action={<Button icon={Lock} onClick={() => setWizardOpen(true)}>{t("quarantine.setUp")}</Button>}
          />
        </Card>
      )}

      {(probe.enabled || probe.active) && (
        <>
          {probe.issues.map((i) => <Banner key={i} tone="warn">{i}</Banner>)}

          <Card title={t("quarantine.statusTitle")} icon={ShieldCheck}
            action={probe.active
              ? <Pill tone="ok" live>{t("quarantine.active")}</Pill>
              : <Pill tone="danger">{t("quarantine.notRunning")}</Pill>}>
            <div className="space-y-4">
              <div>
                <div className="text-small font-medium mb-1">{t("quarantine.modeLabel")}</div>
                <SegmentedControl<Mode>
                  ariaLabel={t("quarantine.modeLabel")}
                  options={[
                    { value: "internet", label: t("quarantine.modeInternet") },
                    { value: "nothing", label: t("quarantine.modeNothing") },
                  ]}
                  value={probe.mode}
                  onChange={(m) => { if (m !== probe.mode && !busy) run(() => api.quarantineMode(m), t("quarantine.saved")); }}
                />
                <p className="text-small text-muted mt-1">{probe.mode === "internet" ? t("quarantine.modeInternetHelp") : t("quarantine.modeNothingHelp")}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-small font-medium">{t("quarantine.zonesLabel")}</span>
                {protectedZones.map((z) => <Pill key={z} tone="accent">{z}</Pill>)}
                <Button size="sm" variant="ghost" onClick={() => setZonesOpen(true)}>{t("quarantine.change")}</Button>
              </div>
              <div className="flex justify-end">
                <Button variant="danger" icon={ShieldOff} disabled={busy} onClick={() => setConfirmOff(true)}>{t("quarantine.turnOff")}</Button>
              </div>
            </div>
          </Card>

          <WifiLayerCard probe={probe} busy={busy} onToggle={setWifiConfirm} />
          <RadiusCard probe={probe} busy={busy} run={run} />

          <Card title={t("quarantine.pauseTitle")} icon={Pause}>
            {pauseActive ? (
              <Banner tone="warn" action={<Button size="sm" icon={Play} disabled={busy} onClick={() => run(() => api.quarantineResume(), t("quarantine.resumed"))}>{t("quarantine.resume")}</Button>}>
                {probe.pause.kind === "learn"
                  ? t("quarantine.pausedLearn", { minutes: Math.ceil(((probe.pause.until ?? 0) - now) / 60), count: probe.pause.learned?.length ?? 0 })
                  : t("quarantine.pausedOff", { minutes: Math.ceil(((probe.pause.until ?? 0) - now) / 60) })}
              </Banner>
            ) : (
              <div className="space-y-3">
                <p className="text-small text-muted">{t("quarantine.pauseHelp")}</p>
                <p className="text-small text-muted">{t("quarantine.pauseOffNote")}</p>
                {probe.wifi.enabled && <p className="text-small text-muted">{t("quarantine.wifiPauseNote")}</p>}
                <div className="flex flex-wrap items-center gap-2">
                  <SegmentedControl<string>
                    ariaLabel={t("quarantine.pauseLength")}
                    size="sm"
                    options={["15", "30", "60", "120"].map((m) => ({ value: m, label: t("quarantine.minutes", { count: Number(m) }) }))}
                    value={pauseMinutes}
                    onChange={setPauseMinutes}
                  />
                  <Button size="sm" icon={UserCheck} disabled={busy} onClick={() => run(() => api.quarantinePause(Number(pauseMinutes), "learn"), t("quarantine.pausedOk"))}>{t("quarantine.pauseLearn")}</Button>
                  <Button size="sm" variant="secondary" icon={Pause} disabled={busy} onClick={() => run(() => api.quarantinePause(Number(pauseMinutes), "off"), t("quarantine.pausedOk"))}>{t("quarantine.pauseOff")}</Button>
                </div>
              </div>
            )}
          </Card>

          <DetectCard probe={probe} busy={busy} run={run} label={label}
            onRevoke={(mac) => { const d = probe.approved.find((x) => x.mac === mac); if (d) { setRevokePair(true); setRevoke(d); } }} />

          <Card title={t("quarantine.pendingTitle", { count: probe.pending.length })} icon={Lock}
            action={probe.pending.length > 1 && (
              <Button size="sm" variant="secondary" disabled={busy}
                onClick={() => run(() => api.quarantineApprove(probe.pending.map((d) => ({ mac: d.mac, name: names[d.mac] }))), t("quarantine.approvedOk"))}>
                {t("quarantine.approveAll")}
              </Button>
            )}>
            {probe.pending.length === 0 ? (
              <p className="text-small text-muted">{t("quarantine.pendingEmpty")}</p>
            ) : (
              <ul className="divide-y divide-border">
                {pendingRows.map(({ d, twin }) => (
                  <li key={d.mac} id={`q-pending-${d.mac}`}
                    className={`py-3 flex flex-wrap items-center gap-3 ${linked && (d.mac === linked || twin?.mac === linked) ? "rounded-md ring-2 ring-accent px-2" : ""}`}>
                    <div className="min-w-0 flex-1">
                      <div className="font-medium truncate">{label(twin && !d.name && !d.hostname ? twin : d)}</div>
                      {(() => {
                        const nets = [...new Set([...(d.networks ?? []), ...(twin?.networks ?? [])])];
                        return nets.length ? <div className="text-small">{t("quarantine.wantsNetwork", { networks: nets.join(", ") })}</div> : null;
                      })()}
                      <div className="text-small text-muted mono">{d.mac}{d.ip ? ` · ${d.ip}` : ""}</div>
                      {twin ? <div className="text-small text-muted mono">{twin.mac}{twin.ip ? ` · ${twin.ip}` : ""}</div> : null}
                      {twin ? <div className="text-small text-accent">{t("quarantine.twinHint")}</div> : null}
                      {d.last_seen ? <div className="text-small text-muted">{t("quarantine.lastSeen", { when: fmtDate(d.last_seen) })}</div> : null}
                      {d.pair_of || twin?.pair_of ? (
                        <div className="text-small text-accent">
                          {t("quarantine.pairOf", { name: (() => { const pm = d.pair_of || twin?.pair_of; const a = probe.approved.find((x) => x.mac === pm); return a ? label(a) : pm; })() })}
                        </div>
                      ) : null}
                    </div>
                    <div className="w-48">
                      <Input placeholder={t("quarantine.namePlaceholder")} value={names[d.mac] ?? ""} maxLength={64}
                        onChange={(e) => setNames((n) => ({ ...n, [d.mac]: e.target.value }))} />
                    </div>
                    <Button size="sm" icon={Check} disabled={busy}
                      onClick={() => run(() => api.quarantineApprove([d, ...(twin ? [twin] : [])].map((x) => ({ mac: x.mac, name: names[d.mac] }))), t("quarantine.approvedOk"))}>
                      {twin ? t("quarantine.approveBoth") : t("quarantine.approve")}
                    </Button>
                    <Button size="sm" variant="ghost" icon={Trash2} disabled={busy} aria-label={t("quarantine.forget")}
                      onClick={() => run(async () => {
                        // Both are tried; the first failure is reported.
                        const [a, b] = await Promise.allSettled([d, ...(twin ? [twin] : [])].map((x) => api.quarantineForget(x.mac)));
                        for (const r of [a, b]) if (r && r.status === "rejected") throw r.reason;
                        return b?.status === "fulfilled" ? b.value : a.status === "fulfilled" ? a.value : {};
                      })}>
                      {t("quarantine.forget")}
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <ApprovedCard devices={probe.approved} you={you} busy={busy} label={label}
            onRevoke={(d) => { setRevokePair(true); setRevoke(d); }} />
        </>
      )}

      {wizardOpen && probe && (
        <EnableWizard probe={probe} you={you} busy={busy} onClose={() => setWizardOpen(false)}
          onEnable={async (body) => {
            if (await run(() => api.quarantineEnable(body), t("quarantine.enabledOk"))) setWizardOpen(false);
          }} />
      )}
      {zonesOpen && probe && (
        <ZonesModal probe={probe} you={you} busy={busy} onClose={() => setZonesOpen(false)}
          onSave={async (zones, allow) => {
            if (await run(() => api.quarantineZones(zones, allow), t("quarantine.saved"))) setZonesOpen(false);
          }} />
      )}
      <ConfirmDialog open={confirmOff} onClose={() => setConfirmOff(false)} busy={busy}
        title={t("quarantine.turnOffTitle")} consequence={t("quarantine.turnOffBody")} confirmLabel={t("quarantine.turnOff")}
        onConfirm={async () => { await run(() => api.quarantineDisable(), t("quarantine.disabledOk")); setConfirmOff(false); }} />
      <ConfirmDialog open={revoke !== null} onClose={() => setRevoke(null)} busy={busy}
        title={t("quarantine.revokeTitle", { name: revoke ? label(revoke) : "" })}
        consequence={you ? t("quarantine.revokeBody") : `${t("quarantine.revokeBody")} ${t("quarantine.revokeYouUnknown")}`}
        confirmLabel={t("quarantine.revoke")}
        onConfirm={async () => {
          if (revoke) {
            const partner = revokePartner && revokePair ? revokePartner : undefined;
            await run(async () => {
              const r = await api.quarantineRevoke(revoke.mac, !you);
              return partner ? api.quarantineRevoke(partner.mac, !you) : r;
            }, t("quarantine.revokedOk"));
          }
          setRevoke(null);
        }}>
        {revokePartner && (
          <label className="mt-3 flex items-start gap-2 text-small">
            <input type="checkbox" className="mt-0.5" checked={revokePair} onChange={(e) => setRevokePair(e.target.checked)} />
            <span>{t("quarantine.revokePair", { mac: revokePartner.mac })}</span>
          </label>
        )}
      </ConfirmDialog>
      <ConfirmDialog open={wifiConfirm !== null} onClose={() => setWifiConfirm(null)} busy={busy}
        title={wifiConfirm === "on" ? t("quarantine.wifiOnTitle") : t("quarantine.wifiOffTitle")}
        consequence={wifiConfirm === "on"
          ? `${t("quarantine.wifiOnBody", { ssids: probe.wifi.ssids.filter((x) => x.covered).map((x) => x.ssid || x.section).join(", ") })}${you ? "" : ` ${t("quarantine.youUnknown")}`}`
          : t("quarantine.wifiOffBody")}
        confirmLabel={wifiConfirm === "on" ? t("quarantine.wifiTurnOn") : t("quarantine.wifiTurnOff")}
        onConfirm={async () => {
          const on = wifiConfirm === "on";
          await run(() => api.quarantineWifi(on, on && !you), on ? t("quarantine.wifiOnOk") : t("quarantine.wifiOffOk"));
          setWifiConfirm(null);
        }} />
      <RollbackConfirmModal pending={rc.pending} seconds={rc.seconds} onKeep={rc.keep} onRevert={rc.revert} />
    </div>
  );
}

/** One piece of copied-MAC evidence, as a line. */
function SignalLine({ s }: { s: QSignal }) {
  const { t } = useTranslation();
  const name = t(`quarantine.signal.${s.kind}`, { defaultValue: s.kind });
  return (
    <li className="text-small">
      <span className={s.strong ? "font-medium text-danger" : "font-medium"}>{name}</span>: <span className="mono break-all">{s.now}</span>
      {s.was && s.was.length > 0 && <span className="text-muted"> · {t("quarantine.signalKnown", { values: s.was.join(" | ") })}</span>}
    </li>
  );
}

/** Copied-MAC detection (phase 5): its switch, the optional automatic
 * move back to quarantine, and the reports. */
function DetectCard({ probe, busy, run, label, onRevoke }: {
  probe: QuarantineProbe;
  busy: boolean;
  run: (fn: () => Promise<QResult>, ok?: string) => Promise<boolean>;
  label: (d: QDevice) => string;
  onRevoke: (mac: string) => void;
}) {
  const { t } = useTranslation();
  const d = probe.detect;
  const [confirmAuto, setConfirmAuto] = useState(false);
  const [confirmOff, setConfirmOff] = useState(false);
  const alerts = d.suspects.filter((s) => s.level === "alert" && !s.action).length;
  return (
    <Card title={t("quarantine.detectTitle")} icon={Fingerprint}
      action={<div className="flex items-center gap-2">
        {alerts > 0 && <Pill tone="danger">{t("quarantine.detectAlerts", { count: alerts })}</Pill>}
        <Toggle checked={d.enabled} busy={busy} label={t("quarantine.detectTitle")}
          onChange={(v) => { if (v) run(() => api.quarantineDetect(true, false), t("quarantine.detectOnOk")); else setConfirmOff(true); }} />
      </div>}>
      <div className="space-y-3">
        <p className="text-small text-muted">{t("quarantine.detectHelp")}</p>
        {d.enabled && (
          <>
            <p className="text-small">
              {d.learning > 0 && d.learn_until
                ? t("quarantine.detectLearning", { count: d.learning, total: d.profiles, when: fmtDate(d.learn_until) })
                : t("quarantine.detectWatching", { count: d.profiles })}
            </p>
            {d.sources.length > 0 && !d.sources.includes("fingerprints") && <Banner tone="warn">{t("quarantine.detectNoFingerprints")}</Banner>}
            {d.sources.length > 0 && (
              <p className="text-small text-muted">{t("quarantine.detectSources", { sources: d.sources.map((s) => t(`quarantine.source2.${s}`, { defaultValue: s })).join(", ") })}</p>
            )}
            <label className="flex items-start gap-2 text-small">
              <input type="checkbox" className="mt-0.5" checked={d.auto} disabled={busy}
                onChange={(e) => { if (e.target.checked) setConfirmAuto(true); else run(() => api.quarantineDetect(true, false), t("quarantine.saved")); }} />
              <span>
                <span className="font-medium">{t("quarantine.detectAuto")}</span>
                <span className="block text-muted">{t("quarantine.detectAutoHelp")}</span>
              </span>
            </label>
            {d.suspects.length === 0 ? (
              <p className="text-small text-muted">{t("quarantine.detectNone")}</p>
            ) : (
              <ul className="divide-y divide-border">
                {d.suspects.map((s) => (
                  <li key={s.mac} className="py-3 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{label(s)}</span>
                      {s.action === "quarantined"
                        ? <Pill tone="accent">{t("quarantine.detectMoved")}</Pill>
                        : s.level === "alert" ? <Pill tone="danger">{t("quarantine.detectAlert")}</Pill> : <Pill tone="warn">{t("quarantine.detectNotice")}</Pill>}
                      <span className="text-small text-muted mono">{s.mac}{s.ip ? ` · ${s.ip}` : ""}</span>
                    </div>
                    <ul className="space-y-0.5">{s.signals.map((g, i) => <SignalLine key={`${g.kind}-${i}`} s={g} />)}</ul>
                    <div className="text-small text-muted">
                      {s.action === "quarantined" && s.action_at
                        ? t("quarantine.detectMovedAt", { when: fmtDate(s.action_at) })
                        : t("quarantine.detectSeen", { first: fmtDate(s.first), last: fmtDate(s.last) })}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {!s.action && (
                        <>
                          <Button size="sm" icon={Check} disabled={busy}
                            onClick={() => run(() => api.quarantineSuspect(s.mac, "same"), t("quarantine.detectSameOk"))}>{t("quarantine.detectSame")}</Button>
                          <Button size="sm" variant="secondary" icon={UserX} disabled={busy} onClick={() => onRevoke(s.mac)}>{t("quarantine.detectMove")}</Button>
                        </>
                      )}
                      <Button size="sm" variant="ghost" icon={Trash2} disabled={busy}
                        onClick={() => run(() => api.quarantineSuspect(s.mac, "dismiss"))}>{t("quarantine.detectDismiss")}</Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>
      <ConfirmDialog open={confirmAuto} onClose={() => setConfirmAuto(false)} busy={busy}
        title={t("quarantine.detectAutoTitle")} consequence={t("quarantine.detectAutoBody")} confirmLabel={t("quarantine.detectAutoOn")}
        onConfirm={async () => { await run(() => api.quarantineDetect(true, true), t("quarantine.saved")); setConfirmAuto(false); }} />
      <ConfirmDialog open={confirmOff} onClose={() => setConfirmOff(false)} busy={busy}
        title={t("quarantine.detectOffTitle")} consequence={t("quarantine.detectOffBody")} confirmLabel={t("quarantine.detectOff")}
        onConfirm={async () => { await run(() => api.quarantineDetect(false, false), t("quarantine.detectOffOk")); setConfirmOff(false); }} />
    </Card>
  );
}

/** The Wi-Fi layer: this router's own SSIDs move unapproved devices to a
 * quarantine network. Turning it on runs inside the rollback-confirm window. */
function WifiLayerCard({ probe, busy, onToggle }: { probe: QuarantineProbe; busy: boolean; onToggle: (v: "on" | "off") => void }) {
  const { t } = useTranslation();
  const w = probe.wifi;
  if (w.ssids.length === 0 && !w.enabled) return null;
  const covered = w.ssids.filter((s) => s.covered);
  return (
    <Card title={t("quarantine.wifiTitle")} icon={Wifi}
      action={w.enabled ? <Pill tone="ok" live>{t("quarantine.wifiOn")}</Pill> : <Pill>{t("quarantine.wifiOff")}</Pill>}>
      <div className="space-y-3">
        <p className="text-small text-muted">{t("quarantine.wifiHelp")}</p>
        {w.enabled && <p className="text-small text-muted">{t("quarantine.wifiJoinNote")}</p>}
        {!w.enabled && w.off_reason && <Banner tone="warn">{t("quarantine.wifiTurnedOff", { reason: w.off_reason })}</Banner>}
        {w.issues.map((i) => <Banner key={i} tone="warn">{i}</Banner>)}
        {w.enabled && (
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-small">
            {w.subnet && <span>{t("quarantine.wifiSubnet", { subnet: w.subnet })}</span>}
            <span className="text-muted">{t("quarantine.wifiQuarantined", { count: w.quarantined })}</span>
          </div>
        )}
        <ul className="space-y-1">
          {w.ssids.map((s) => (
            <li key={s.section} className="flex flex-wrap items-center gap-2 text-small">
              <span className="font-medium">{s.ssid || s.section}</span>
              <span className="text-muted">{s.network}</span>
              {s.covered
                ? <Pill tone={s.applied ? "ok" : "accent"}>{t("quarantine.wifiCovered")}</Pill>
                : <span className="text-muted">{t("quarantine.wifiNotCovered")}{s.reason ? ` · ${s.reason}` : ""}</span>}
            </li>
          ))}
        </ul>
        {!w.enabled && covered.length === 0 && <p className="text-small text-muted">{t("quarantine.wifiNoneCovered")}</p>}
        <div className="flex justify-end">
          {w.enabled
            ? <Button variant="secondary" disabled={busy} onClick={() => onToggle("off")}>{t("quarantine.wifiTurnOff")}</Button>
            : <Button icon={Wifi} disabled={busy || covered.length === 0} onClick={() => onToggle("on")}>{t("quarantine.wifiTurnOn")}</Button>}
        </div>
      </div>
    </Card>
  );
}

/** The access-point layer: a RADIUS server for MAC authentication. Turning
 * it on only admits RADIUS and starts answering; joining changes once the
 * access point is set to ask, which the user does there. */
function RadiusCard({ probe, busy, run }: { probe: QuarantineProbe; busy: boolean; run: (fn: () => Promise<QResult>, ok?: string) => Promise<boolean> }) {
  const { t } = useTranslation();
  const { push } = useToast();
  const r = probe.radius;
  const zones = probe.zones.filter((z) => !z.wan);
  const [pick, setPick] = useState<Set<string>>(new Set());
  const [secret, setSecret] = useState("");
  const [confirmOff, setConfirmOff] = useState(false);
  const [confirmNew, setConfirmNew] = useState(false);
  const fail = (e: unknown) => push({ tone: "danger", text: t("quarantine.actionFailed"), detail: e instanceof Error ? e.message : String(e) });
  const show = async () => { try { setSecret((await api.quarantineRadiusSecret()).secret); } catch (e) { fail(e); } };
  const renew = async () => { try { setSecret((await api.quarantineRadiusNewSecret()).secret); } catch (e) { fail(e); } finally { setConfirmNew(false); } };
  const s = r.stats;
  return (
    <Card title={t("quarantine.radiusTitle")} icon={Radio}
      action={r.enabled
        ? (s.listening ? <Pill tone="ok" live>{t("quarantine.radiusListening")}</Pill> : <Pill tone="danger">{t("quarantine.radiusNotListening")}</Pill>)
        : <Pill>{t("quarantine.wifiOff")}</Pill>}>
      <div className="space-y-3">
        <p className="text-small text-muted">{t("quarantine.radiusHelp")}</p>
        {!r.enabled ? (
          <>
            <div className="text-small font-medium">{t("quarantine.radiusZones")}</div>
            <div className="flex flex-wrap gap-3">
              {zones.map((z) => (
                <label key={z.name} className="flex items-center gap-2 text-small">
                  <input type="checkbox" checked={pick.has(z.name)}
                    onChange={() => setPick((p) => { const n = new Set(p); if (n.has(z.name)) n.delete(z.name); else n.add(z.name); return n; })} />
                  {z.name}
                </label>
              ))}
            </div>
            <p className="text-small text-muted">{t("quarantine.radiusOutage")}</p>
            <div className="flex justify-end">
              <Button icon={Radio} disabled={busy || pick.size === 0}
                onClick={() => run(() => api.quarantineRadius(true, [...pick]), t("quarantine.radiusOnOk"))}>{t("quarantine.radiusTurnOn")}</Button>
            </div>
          </>
        ) : (
          <>
            {s.error && <Banner tone="danger">{s.error}</Banner>}
            {s.bad_auth > 0 && <Banner tone="warn">{t("quarantine.radiusBadAuth", { count: s.bad_auth })}</Banner>}
            {s.credential > 0 && <Banner tone="warn">{t("quarantine.radiusCredential", { count: s.credential })}</Banner>}
            <div className="text-small space-y-1">
              {s.last_request
                ? <div>{t("quarantine.radiusLast", { when: fmtDate(s.last_request) })} · {t("quarantine.radiusStats", { accepted: s.accepted, rejected: s.rejected })}</div>
                : <div className="text-muted">{t("quarantine.radiusNoRequest")}</div>}
              {s.clients.length > 0 && <div className="text-muted">{t("quarantine.radiusSeen", { clients: s.clients.join(", "), ssids: s.ssids.join(", ") || "-" })}</div>}
            </div>
            <div className="rounded border border-border p-3 space-y-2">
              <div className="text-small font-medium">{t("quarantine.radiusSetup")}</div>
              <div className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 text-small">
                <span className="text-muted">{t("quarantine.radiusServer")}</span><span className="mono">{r.addresses.join(", ") || "-"}</span>
                <span className="text-muted">{t("quarantine.radiusPort")}</span><span className="mono">{r.port}</span>
                <span className="text-muted">{t("quarantine.radiusSecret")}</span>
                <span className="flex flex-wrap items-center gap-2">
                  {secret ? <span className="mono select-all">{secret}</span> : <Button size="sm" variant="secondary" onClick={show}>{t("quarantine.radiusShowSecret")}</Button>}
                  <Button size="sm" variant="ghost" onClick={() => setConfirmNew(true)}>{t("quarantine.radiusNewSecret")}</Button>
                </span>
              </div>
              <p className="text-small text-muted">{t("quarantine.radiusStepsUnifi")}</p>
            </div>
            <p className="text-small text-muted">{t("quarantine.radiusOutage")}</p>
            <div className="flex justify-end">
              <Button variant="secondary" disabled={busy} onClick={() => setConfirmOff(true)}>{t("quarantine.radiusTurnOff")}</Button>
            </div>
          </>
        )}
      </div>
      <ConfirmDialog open={confirmOff} onClose={() => setConfirmOff(false)} busy={busy}
        title={t("quarantine.radiusOffTitle")} consequence={t("quarantine.radiusOffBody")} confirmLabel={t("quarantine.radiusTurnOff")}
        onConfirm={async () => { await run(() => api.quarantineRadius(false, []), t("quarantine.radiusOffOk")); setConfirmOff(false); setSecret(""); }} />
      <ConfirmDialog open={confirmNew} onClose={() => setConfirmNew(false)} busy={busy}
        title={t("quarantine.radiusNewSecretTitle")} consequence={t("quarantine.radiusNewSecretBody")} confirmLabel={t("quarantine.radiusNewSecret")}
        onConfirm={renew} />
    </Card>
  );
}

function ZoneChecklist({ probe, selected, onToggle }: { probe: QuarantineProbe; selected: Set<string>; onToggle: (z: string) => void }) {
  const { t } = useTranslation();
  return (
    <ul className="space-y-2">
      {probe.zones.filter((z) => !z.wan).map((z) => (
        <li key={z.name}>
          <label className="flex items-start gap-2 cursor-pointer">
            <input type="checkbox" className="mt-1" checked={selected.has(z.name)} onChange={() => onToggle(z.name)} />
            <span>
              <span className="font-medium">{z.name}</span>
              <span className="text-small text-muted"> · {z.networks.join(", ") || t("quarantine.noNetworks")}</span>
              {z.suggested && <span className="text-small text-muted"> · {t("quarantine.clientZone")}</span>}
            </span>
          </label>
        </li>
      ))}
    </ul>
  );
}

function useZoneSelection(initial: string[]) {
  const [selected, setSelected] = useState(() => new Set(initial));
  const toggle = (z: string) => setSelected((s) => {
    const n = new Set(s);
    if (n.has(z)) n.delete(z); else n.add(z);
    return n;
  });
  return { selected, toggle };
}

function ZonesModal({ probe, you, busy, onClose, onSave }: { probe: QuarantineProbe; you: string; busy: boolean; onClose: () => void; onSave: (z: string[], allow: boolean) => void }) {
  const { t } = useTranslation();
  const [accept, setAccept] = useState(false);
  // Only zones that can still be protected: a zone that became an uplink,
  // or was removed, would otherwise make every save fail.
  const { selected, toggle } = useZoneSelection(probe.zones.filter((z) => z.protected && !z.wan).map((z) => z.name));
  return (
    <Modal open onClose={onClose} title={t("quarantine.zonesTitle")}
      footer={<>
        <Button variant="secondary" onClick={onClose}>{t("common.cancel")}</Button>
        <Button loading={busy} disabled={selected.size === 0 || (!you && !accept)} onClick={() => onSave([...selected], !you && accept)}>{t("common.save")}</Button>
      </>}>
      <p className="text-small text-muted mb-3">{t("quarantine.zonesHelp")}</p>
      <ZoneChecklist probe={probe} selected={selected} onToggle={toggle} />
      {!you && (
        <Banner tone="danger" className="mt-3">
          <label className="flex items-start gap-2">
            <input type="checkbox" className="mt-1" checked={accept} onChange={(e) => setAccept(e.target.checked)} />
            <span>{t("quarantine.youUnknown")}</span>
          </label>
        </Banner>
      )}
    </Modal>
  );
}

function EnableWizard({ probe, you, busy, onClose, onEnable }: {
  probe: QuarantineProbe;
  you: string;
  busy: boolean;
  onClose: () => void;
  onEnable: (body: { mode: Mode; zones: string[]; approve: { mac: string; name?: string }[]; allow_no_requester?: boolean }) => void;
}) {
  const { t } = useTranslation();
  const label = useLabel();
  const [mode, setMode] = useState<Mode>(probe.mode ?? "internet");
  const { selected: zones, toggle: toggleZone } = useZoneSelection(probe.zones.filter((z) => z.suggested).map((z) => z.name));
  const [candidates, setCandidates] = useState<QCandidate[]>();
  const [trusted, setTrusted] = useState<Set<string>>(new Set());
  const [accept, setAccept] = useState(false);

  useEffect(() => {
    api.quarantineCandidates().then((r) => {
      setCandidates(r.candidates);
      setTrusted(new Set(r.candidates.map((c) => c.mac)));
    }).catch(() => setCandidates([]));
  }, []);

  const toggle = (mac: string) => setTrusted((s) => {
    const n = new Set(s);
    if (n.has(mac)) n.delete(mac); else n.add(mac);
    return n;
  });
  const youUnknown = !you;
  const youRandom = (candidates ?? []).some((c) => c.requester && c.random);
  const canEnable = zones.size > 0 && candidates !== undefined && (!youUnknown || accept);
  const approve = useMemo(() => (candidates ?? []).filter((c) => trusted.has(c.mac) || c.requester).map((c) => ({ mac: c.mac, name: c.name })), [candidates, trusted]);

  return (
    <Modal open xlarge onClose={onClose} title={t("quarantine.wizardTitle")}
      footer={<>
        <Button variant="secondary" onClick={onClose}>{t("common.cancel")}</Button>
        <Button icon={Lock} loading={busy} disabled={!canEnable}
          onClick={() => onEnable({ mode, zones: [...zones], approve, allow_no_requester: youUnknown && accept })}>
          {t("quarantine.turnOn")}
        </Button>
      </>}>
      <div className="space-y-5">
        <section>
          <h3 className="text-body font-semibold mb-1">{t("quarantine.step1")}</h3>
          <SegmentedControl<Mode> ariaLabel={t("quarantine.modeLabel")}
            options={[{ value: "internet", label: t("quarantine.modeInternet") }, { value: "nothing", label: t("quarantine.modeNothing") }]}
            value={mode} onChange={setMode} />
          <p className="text-small text-muted mt-1">{mode === "internet" ? t("quarantine.modeInternetHelp") : t("quarantine.modeNothingHelp")}</p>
        </section>
        <section>
          <h3 className="text-body font-semibold mb-1">{t("quarantine.step2")}</h3>
          <p className="text-small text-muted mb-2">{t("quarantine.zonesHelp")}</p>
          <ZoneChecklist probe={probe} selected={zones} onToggle={toggleZone} />
        </section>
        <section>
          <h3 className="text-body font-semibold mb-1">{t("quarantine.step3", { count: approve.length })}</h3>
          <p className="text-small text-muted mb-2">{t("quarantine.baselineHelp")}</p>
          {youRandom && <Banner tone="warn" className="mb-2">{t("quarantine.youRandom")}</Banner>}
          {candidates === undefined ? <SkeletonRows rows={4} /> : (
            <>
              <div className="flex gap-2 mb-2">
                <Button size="sm" variant="ghost" onClick={() => setTrusted(new Set(candidates.map((c) => c.mac)))}>{t("quarantine.selectAll")}</Button>
                <Button size="sm" variant="ghost" onClick={() => setTrusted(new Set())}>{t("quarantine.selectNone")}</Button>
              </div>
              <ul className="divide-y divide-border max-h-80 overflow-auto">
                {candidates.map((c) => (
                  <li key={c.mac} className="py-2">
                    <label className="flex items-start gap-2 cursor-pointer">
                      <input type="checkbox" className="mt-1" disabled={c.requester} checked={c.requester || trusted.has(c.mac)} onChange={() => toggle(c.mac)} />
                      <span className="min-w-0">
                        <span className="font-medium">{label(c)}</span>
                        {c.requester && <> <Pill tone="accent">{t("quarantine.you")}</Pill></>}
                        <span className="block text-small text-muted mono">{c.mac}{c.ip ? ` · ${c.ip}` : ""} · {c.sources.join(", ")}</span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
        {youUnknown && (
          <Banner tone="danger">
            <label className="flex items-start gap-2">
              <input type="checkbox" className="mt-1" checked={accept} onChange={(e) => setAccept(e.target.checked)} />
              <span>{t("quarantine.youUnknown")}</span>
            </label>
          </Banner>
        )}
        <Banner tone="info">{t("quarantine.confirmNote")}</Banner>
      </div>
    </Modal>
  );
}

/** Where an approval came from, grouped for the filter: "panel" (the device
 * the panel was used from) counts as approved by you. */
type Source = "all" | "baseline" | "manual" | "pause" | "mlo";
const SOURCES: Source[] = ["all", "baseline", "manual", "pause", "mlo"];
const sourceOf = (via?: string): Source =>
  via === "baseline" || via === "pause" || via === "mlo" ? via : "manual";
const PAGE = 25;

/** The MAC a link into this page names (`#/quarantine?mac=…`, as NetPulse's
 *  device list builds it), or "" when there is none or it is not a MAC. */
function macFromHash(hash: string): string {
  const i = hash.indexOf("?");
  if (i < 0) return "";
  const mac = (new URLSearchParams(hash.slice(i + 1)).get("mac") ?? "").trim().toLowerCase();
  return /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac) ? mac : "";
}

/** The MAC the page's address names, following later changes to it. */
function useLinkedMac(): string {
  const [mac, setMac] = useState(() => macFromHash(window.location.hash));
  useEffect(() => {
    const on = () => setMac(macFromHash(window.location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return mac;
}

/** Lowercase hex digits only, so "AA-BB", "aa:bb" and "aabb" all match. */
const hexOnly = (s: string) => s.toLowerCase().replace(/[^0-9a-f]/g, "");

/**
 * The approved devices: a search over every name, address and IP, a filter
 * by where each approval came from (with counts), two sort orders, and
 * paging, so a long list stays easy to scan.
 */
function ApprovedCard({ devices, you, busy, label, onRevoke }: {
  devices: QDevice[];
  you: string;
  busy: boolean;
  label: (d: QDevice) => string;
  onRevoke: (d: QDevice) => void;
}) {
  const { t } = useTranslation();
  // A link from NetPulse to an approved device opens the list on it.
  const linked = useLinkedMac();
  const [query, setQuery] = useState("");
  // Once per link: the list reloads every few seconds, and a search the
  // user changes afterwards must stay theirs.
  const linkedApproved = !!linked && devices.some((d) => d.mac === linked);
  useEffect(() => {
    if (linkedApproved) setQuery(linked);
  }, [linked, linkedApproved]);
  const [source, setSource] = useState<Source>("all");
  const [sort, setSort] = useState<"name" | "recent">("name");
  const [shown, setShown] = useState(PAGE);

  const counts = useMemo(() => {
    const c: Record<Source, number> = { all: devices.length, baseline: 0, manual: 0, pause: 0, mlo: 0 };
    for (const d of devices) c[sourceOf(d.via)]++;
    return c;
  }, [devices]);

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    const qHex = hexOnly(q);
    const out = devices.filter((d) => {
      if (source !== "all" && sourceOf(d.via) !== source) return false;
      if (!q) return true;
      const text = [label(d), d.name, d.hostname, d.vendor, d.ip, d.mac].filter(Boolean).join(" ").toLowerCase();
      // A MAC typed with any separators (or none) still matches.
      return text.includes(q) || (qHex.length >= 4 && hexOnly(d.mac).includes(qHex));
    });
    out.sort((a, b) => {
      if (sort === "recent" && (b.at ?? 0) !== (a.at ?? 0)) return (b.at ?? 0) - (a.at ?? 0);
      return label(a).localeCompare(label(b)) || a.mac.localeCompare(b.mac);
    });
    return out;
  }, [devices, query, source, sort, label]);

  // A new search or filter starts from the top of the list.
  useEffect(() => setShown(PAGE), [query, source, sort]);

  return (
    <Card title={t("quarantine.approvedTitle", { count: devices.length })} icon={UserCheck}>
      <div className="space-y-3">
        {devices.length > 0 && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <div className="min-w-[12rem] flex-1">
                <Input icon={Search} type="search" value={query} onChange={(e) => setQuery(e.target.value)}
                  placeholder={t("quarantine.approvedSearch")} aria-label={t("quarantine.approvedSearch")} />
              </div>
              <SegmentedControl<"name" | "recent">
                ariaLabel={t("quarantine.approvedSort")}
                size="sm"
                options={[{ value: "name", label: t("quarantine.sortName") }, { value: "recent", label: t("quarantine.sortRecent") }]}
                value={sort}
                onChange={setSort}
              />
            </div>
            <div className="flex flex-wrap gap-2" role="group" aria-label={t("quarantine.approvedFilter")}>
              {SOURCES.filter((s) => s === "all" || counts[s] > 0).map((s) => (
                <Button key={s} size="sm" variant={source === s ? "primary" : "secondary"} aria-pressed={source === s}
                  onClick={() => setSource(s)}>
                  {t(`quarantine.source.${s}`)} ({counts[s]})
                </Button>
              ))}
            </div>
          </>
        )}
        {list.length === 0 ? (
          <p className="text-small text-muted">{devices.length === 0 ? t("quarantine.approvedEmpty") : t("quarantine.approvedNoMatch")}</p>
        ) : (
          <ul className="divide-y divide-border">
            {list.slice(0, shown).map((d) => (
              <li key={d.mac} className="py-3 flex flex-wrap items-center gap-3">
                <div className="min-w-0 flex-1">
                  <div className="font-medium truncate flex items-center gap-2">
                    {label(d)}
                    {d.mac === you && <Pill tone="accent">{t("quarantine.you")}</Pill>}
                    {d.via && <Pill tone="muted">{t(`quarantine.via.${d.via}`, { defaultValue: d.via })}</Pill>}
                  </div>
                  <div className="text-small text-muted mono">{d.mac}{d.ip ? ` · ${d.ip}` : ""}</div>
                  {d.at ? <div className="text-small text-muted">{t("quarantine.approvedAt", { when: fmtDate(d.at) })}</div> : null}
                  {(() => {
                    const p = pairPartner(d, devices);
                    return p ? <div className="text-small text-accent">{t("quarantine.pairWith", { mac: p.mac })}</div> : null;
                  })()}
                </div>
                <Button size="sm" variant="ghost" icon={UserX} disabled={busy || d.mac === you}
                  title={d.mac === you ? t("quarantine.cannotRevokeYou") : undefined}
                  onClick={() => onRevoke(d)}>
                  {t("quarantine.revoke")}
                </Button>
              </li>
            ))}
          </ul>
        )}
        {list.length > shown && (
          <div className="flex items-center justify-between gap-2">
            <span className="text-small text-muted">{t("quarantine.approvedShowing", { shown, total: list.length })}</span>
            <Button size="sm" variant="secondary" onClick={() => setShown((n) => n + PAGE)}>{t("quarantine.showMore")}</Button>
          </div>
        )}
      </div>
    </Card>
  );
}

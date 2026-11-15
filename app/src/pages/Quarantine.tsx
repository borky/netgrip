import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, Lock, Pause, Play, Radio, ShieldCheck, ShieldOff, Trash2, UserCheck, UserX, Wifi } from "lucide-react";
import { api } from "../api";
import type { QCandidate, QDevice, QResult, QuarantineProbe } from "../types";
import { Banner, Button, Card, ConfirmDialog, EmptyState, Input, Modal, Pill, SegmentedControl, SkeletonRows, useToast } from "../components/ui";
import { RollbackConfirmModal, useRollbackConfirm } from "../components/rollback";
import { fmtDate } from "../lib/format";

type Mode = "internet" | "nothing";

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
                  <li key={d.mac} className="py-3 flex flex-wrap items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="font-medium truncate">{label(twin && !d.name && !d.hostname ? twin : d)}</div>
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

          <Card title={t("quarantine.approvedTitle", { count: probe.approved.length })} icon={UserCheck}>
            <ul className="divide-y divide-border">
              {probe.approved.map((d) => (
                <li key={d.mac} className="py-3 flex flex-wrap items-center gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="font-medium truncate flex items-center gap-2">
                      {label(d)}
                      {d.mac === you && <Pill tone="accent">{t("quarantine.you")}</Pill>}
                      {d.via && <Pill tone="muted">{t(`quarantine.via.${d.via}`)}</Pill>}
                    </div>
                    <div className="text-small text-muted mono">{d.mac}{d.ip ? ` · ${d.ip}` : ""}</div>
                  </div>
                  <Button size="sm" variant="ghost" icon={UserX} disabled={busy || d.mac === you}
                    title={d.mac === you ? t("quarantine.cannotRevokeYou") : undefined}
                    onClick={() => setRevoke(d)}>
                    {t("quarantine.revoke")}
                  </Button>
                </li>
              ))}
            </ul>
          </Card>
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
        onConfirm={async () => { if (revoke) await run(() => api.quarantineRevoke(revoke.mac, !you), t("quarantine.revokedOk")); setRevoke(null); }} />
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

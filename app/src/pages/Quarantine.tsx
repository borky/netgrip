import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, Lock, Pause, Play, ShieldCheck, ShieldOff, Trash2, UserCheck, UserX } from "lucide-react";
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
                {probe.pending.map((d) => (
                  <li key={d.mac} className="py-3 flex flex-wrap items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="font-medium truncate">{label(d)}</div>
                      <div className="text-small text-muted mono">{d.mac}{d.ip ? ` · ${d.ip}` : ""}</div>
                      {d.last_seen ? <div className="text-small text-muted">{t("quarantine.lastSeen", { when: fmtDate(d.last_seen) })}</div> : null}
                    </div>
                    <div className="w-48">
                      <Input placeholder={t("quarantine.namePlaceholder")} value={names[d.mac] ?? ""} maxLength={64}
                        onChange={(e) => setNames((n) => ({ ...n, [d.mac]: e.target.value }))} />
                    </div>
                    <Button size="sm" icon={Check} disabled={busy}
                      onClick={() => run(() => api.quarantineApprove([{ mac: d.mac, name: names[d.mac] }]), t("quarantine.approvedOk"))}>
                      {t("quarantine.approve")}
                    </Button>
                    <Button size="sm" variant="ghost" icon={Trash2} disabled={busy} aria-label={t("quarantine.forget")}
                      onClick={() => run(() => api.quarantineForget(d.mac))}>
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
      <RollbackConfirmModal pending={rc.pending} seconds={rc.seconds} onKeep={rc.keep} onRevert={rc.revert} />
    </div>
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

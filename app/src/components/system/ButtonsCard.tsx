import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { CircleDot, Plus, Radar, Trash2 } from "lucide-react";
import { api } from "../../api";
import type { ButtonAction, ButtonActionKind, ButtonEvent, ButtonInfo, ButtonNetwork, ButtonPress, ButtonsConfig, ButtonsProbe } from "../../types";
import { Button, Card, Field, Pill, SegmentedControl } from "../ui";
import { fmtDate, fmtTime } from "../../lib/format";

const SELECT = "w-full rounded-lg border bg-elevated px-2 py-1.5 text-small ring-focus";
const HOLDS = [2, 3, 4, 5, 7, 10, 15, 20, 30];
const DURATIONS = [0, 5, 15, 30, 60, 120, 240, 480];
const ACTIONS: ButtonActionKind[] = ["wifi_toggle", "firewall_restart", "access_restart"];

function patternLabel(t: TFunction, a: Pick<ButtonAction, "trigger" | "count" | "seconds">): string {
  if (a.trigger === "hold") return t("buttons.hold", { count: a.seconds ?? 0 });
  return t(`buttons.press${a.count ?? 1}`);
}

function minutesLabel(t: TFunction, m: number): string {
  if (m <= 0) return t("buttons.keep");
  if (m < 60) return t("buttons.minutes", { count: m });
  return t("buttons.hours", { count: m / 60 });
}

function actionLabel(t: TFunction, a: ButtonAction, ssid: Map<string, string>): string {
  switch (a.action) {
    case "wifi_toggle": {
      const name = ssid.get(a.iface ?? "") ?? a.iface ?? "";
      return (a.minutes ?? 0) > 0
        ? t("buttons.doWifiFor", { name, time: minutesLabel(t, a.minutes ?? 0) })
        : t("buttons.doWifi", { name });
    }
    case "firewall_restart":
      return t("buttons.doFirewall");
    case "access_restart":
      return t("buttons.doAccess");
  }
}

/** One line for an event the router logged, in the panel's language. */
function eventLabel(t: TFunction, e: ButtonEvent, ssid: Map<string, string>): string {
  const failed = e.result.startsWith("failed");
  let what: string;
  if (e.action === "wifi_toggle") {
    const [sec = "", state = "", min = "0"] = e.detail.split(" ");
    const name = ssid.get(sec) ?? sec;
    const on = state === "on";
    if (failed) what = t("buttons.evWifiFailed", { name });
    else if (e.result === "reverted" && e.button === "boot") what = t(on ? "buttons.evBackOnBoot" : "buttons.evBackOffBoot", { name });
    else if (e.result === "reverted") what = t(on ? "buttons.evBackOn" : "buttons.evBackOff", { name, time: minutesLabel(t, Number(min)) });
    else if (e.result === "ended") what = t(on ? "buttons.evEndedOn" : "buttons.evEndedOff", { name });
    else if (Number(min) > 0) what = t(on ? "buttons.evOnFor" : "buttons.evOffFor", { name, time: minutesLabel(t, Number(min)) });
    else what = t(on ? "buttons.evOn" : "buttons.evOff", { name });
  } else if (e.action === "firewall_restart") {
    what = t(failed ? "buttons.evFirewallFailed" : "buttons.evFirewall");
  } else if (e.action === "access_restart") {
    const list = e.detail === "-" ? "" : e.detail.split(",").join(", ");
    what = failed
      ? list ? t("buttons.evAccessFailed", { list, error: e.result }) : e.result
      : list ? t("buttons.evAccess", { list }) : t("buttons.evAccessNone");
  } else {
    what = `${e.action} ${e.result}`;
  }
  const m = /^(press|hold)(\d+)$/.exec(e.pattern);
  if (!m) return what;
  const how = m[1] === "hold" ? t("buttons.hold", { count: Number(m[2]) }) : t(`buttons.press${m[2]}`);
  return `${e.button} · ${how}: ${what}`;
}

/** One press event as the router logged it, to tell a new one apart. */
function pressKey(p: ButtonPress): string {
  return `${p.at}|${p.button}|${p.action}|${p.seen}`;
}

/** What a button does on its own, from its original script. */
function stockNote(t: TFunction, b: ButtonInfo, hasMulti: boolean): string[] {
  const out: string[] = [];
  if (b.stock === "reset") out.push(t("buttons.stockReset", { count: b.reserved ?? 5 }));
  else if (b.stock === "wps") out.push(t("buttons.stockWps"));
  else if (b.stock === "rfkill") out.push(t("buttons.stockRfkill"));
  else if (b.stock === "power") out.push(t("buttons.stockPower"));
  else if (b.stock === "reboot") out.push(t("buttons.stockReboot"));
  else if (b.stock === "custom") out.push(t("buttons.stockCustom"));
  if (hasMulti) out.push(t("buttons.multiNote"));
  return out;
}

/** Card "Router buttons": actions a press of a physical button runs, to
 *  get back into a router (turn a Wi-Fi network on for a while, restart
 *  the firewall or the services that give access). */
export function ButtonsCard({ index = 0 }: { index?: number }) {
  const { t } = useTranslation();
  const [p, setP] = useState<ButtonsProbe>();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string }>();
  const [adding, setAdding] = useState<string>();
  // The last press the router had reported when listening started: a
  // different one is the new press. Router times only (the browser's clock
  // may differ). undefined: not listening.
  const [listenBase, setListenBase] = useState<string>();
  const [detected, setDetected] = useState<string>();
  const timer = useRef<number | undefined>(undefined);

  const load = useCallback(() => {
    api.buttons().then(setP).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  // While listening, poll only the last press (cheap) until one comes.
  useEffect(() => {
    if (listenBase === undefined) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await api.buttonsLast();
        if (cancelled) return;
        const lp = r.last_press;
        if (lp && pressKey(lp) !== listenBase) {
          setListenBase(undefined);
          setDetected(lp.switch ? `${lp.button} (${t("buttons.isSwitch")})` : lp.button);
          load();
          return;
        }
        // The router stops listening on its own clock: no time left is
        // reported once it has.
        if (!r.listen_until) {
          setListenBase(undefined);
          load();
          return;
        }
      } catch { /* the next tick tries again */ }
      if (!cancelled) timer.current = window.setTimeout(tick, 2000);
    };
    timer.current = window.setTimeout(tick, 2000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer.current);
    };
  }, [listenBase, load, t]);

  const ssid = useMemo(() => new Map((p?.networks ?? []).map((n) => [n.section, n.ssid || n.section])), [p]);

  if (!p) return null;

  const save = async (cfg: ButtonsConfig) => {
    setBusy(true);
    setMsg(undefined);
    try {
      const r = await api.setButtons(cfg);
      setP(r.state);
      setAdding(undefined);
      setMsg({ tone: "ok", text: t("buttons.saved") });
    } catch (e) {
      setMsg({ tone: "danger", text: e instanceof Error ? e.message : String(e) });
      load();
    } finally {
      setBusy(false);
    }
  };

  const listen = async () => {
    setMsg(undefined);
    setDetected(undefined);
    try {
      const r = await api.listenButtons();
      setP(r.state);
      setListenBase(r.state.last_press ? pressKey(r.state.last_press) : "");
    } catch (e) {
      setMsg({ tone: "danger", text: e instanceof Error ? e.message : String(e) });
    }
  };

  const actions = p.config.actions;
  const remove = (a: ButtonAction) => save({ ...p.config, actions: actions.filter((x) => x !== a) });

  const missing = (p.requirements ?? []).filter((r) => !r.ok);
  const hasWifi = !missing.some((r) => r.for === "wifi");

  if (!p.available) {
    return (
      <Card index={index} title={t("buttons.title")} help="buttons" icon={CircleDot} iconTone="accent">
        <p className="text-small text-muted">{t("buttons.unavailable")}</p>
        <ul className="mt-2 flex flex-col gap-1">
          {missing.filter((r) => r.required).map((r) => (
            <li key={r.name} className="text-caption">
              <span className="font-medium">{r.name}</span>
              <span className="text-muted"> · {t("buttons.package", { pkg: r.package })}</span>
            </li>
          ))}
        </ul>
      </Card>
    );
  }

  return (
    <Card index={index} title={t("buttons.title")} help="buttons" icon={CircleDot} iconTone="accent">
      <p className="text-small text-muted mb-3">{t("buttons.intro")}</p>

      {p.buttons.length === 0 && <p className="text-small text-muted mb-3">{t("buttons.none")}</p>}

      <div className="divide-y divide-border/60">
        {p.buttons.map((b) => {
          const mine = actions.filter((a) => a.button === b.name);
          const hasMulti = mine.some((a) => a.trigger === "press" && (a.count ?? 1) > 1);
          return (
            <div key={b.name} className="py-3 first:pt-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-small font-medium">{b.name}</span>
                {b.managed && <Pill tone="ok">{t("buttons.active")}</Pill>}
                {!b.board && b.pressed && <Pill tone="muted">{t("buttons.detected")}</Pill>}
                {b.switch && <Pill tone="muted">{t("buttons.switchPill")}</Pill>}
                <span className="flex-1" />
                {adding !== b.name && !b.switch && (
                  <Button size="sm" variant="ghost" icon={Plus} disabled={busy || actions.length >= 16} onClick={() => setAdding(b.name)}>
                    {t("buttons.add")}
                  </Button>
                )}
              </div>
              {stockNote(t, b, hasMulti).map((n) => (
                <p key={n} className="text-caption text-muted mt-1">{n}</p>
              ))}
              {mine.length > 0 && (
                <ul className="mt-2 flex flex-col gap-1.5">
                  {mine.map((a) => {
                    const net = a.action === "wifi_toggle" ? p.networks.find((n) => n.section === a.iface) : undefined;
                    return (
                      <li key={`${a.trigger}${a.count ?? a.seconds}`} className="flex items-center gap-2 rounded-md bg-surface-2 px-2.5 py-1.5">
                        <span className="text-caption font-medium shrink-0">{patternLabel(t, a)}</span>
                        <span className="text-caption text-muted min-w-0 flex-1 truncate">{actionLabel(t, a, ssid)}</span>
                        {net && <NetworkState net={net} />}
                        <button type="button" disabled={busy} onClick={() => remove(a)} aria-label={t("buttons.remove")}
                          className="text-muted hover:text-danger ring-focus rounded-sm p-1">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
              {adding === b.name && (
                <AddAction button={b} networks={p.networks} taken={mine} busy={busy} hasWifi={hasWifi}
                  onCancel={() => setAdding(undefined)}
                  onAdd={(a) => save({ ...p.config, actions: [...actions, a] })} />
              )}
            </div>
          );
        })}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="secondary" icon={Radar} disabled={listenBase !== undefined} onClick={listen}>
          {t("buttons.detect")}
        </Button>
        {listenBase !== undefined && <span className="text-caption text-muted">{t("buttons.listening")}</span>}
        {listenBase === undefined && detected && <span className="text-caption text-ok">{t("buttons.detectedIs", { name: detected })}</span>}
      </div>

      {p.leds.length > 0 && (
        <div className="mt-4 max-w-xs">
          <Field label={t("buttons.led")} hint={t("buttons.ledHint")}>
            <select className={SELECT} value={p.config.led} disabled={busy}
              onChange={(e) => save({ ...p.config, led: e.target.value })}>
              <option value="">{t("buttons.noLed")}</option>
              {p.leds.map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </Field>
        </div>
      )}

      {actions.length > 0 && !p.notify && <p className="text-caption text-muted mt-3">{t("buttons.notifyHint")}</p>}

      {missing.length > 0 && (
        <ul className="mt-3 flex flex-col gap-1">
          {missing.map((r) => (
            <li key={r.name} className="text-caption text-muted">
              {t(`buttons.missing.${r.for}`, { name: r.name })} {t("buttons.package", { pkg: r.package })}
            </li>
          ))}
        </ul>
      )}

      {msg && <p className={`text-caption mt-2 ${msg.tone === "ok" ? "text-ok" : "text-danger"}`}>{msg.text}</p>}

      {p.events.length > 0 && (
        <div className="mt-4">
          <p className="text-eyebrow text-faint mb-1.5">{t("buttons.recent")}</p>
          <ul className="flex flex-col gap-1">
            {p.events.slice(0, 10).map((e, i) => (
              <li key={i} className="flex gap-2 text-caption">
                <span className="text-muted shrink-0 tabular-nums">{fmtDate(e.at)}</span>
                <span className={e.result.startsWith("failed") ? "text-danger" : ""}>{eventLabel(t, e, ssid)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

function NetworkState({ net }: { net: ButtonNetwork }) {
  const { t } = useTranslation();
  if (net.until && net.until * 1000 > Date.now()) {
    return <Pill tone="warn">{t(net.disabled ? "buttons.offUntil" : "buttons.onUntil", { time: fmtTime(net.until) })}</Pill>;
  }
  return <Pill tone={net.disabled ? "muted" : "ok"}>{t(net.disabled ? "buttons.netOff" : "buttons.netOn")}</Pill>;
}

function AddAction({ button, networks, taken, busy, hasWifi, onAdd, onCancel }: {
  button: ButtonInfo;
  hasWifi: boolean;
  networks: ButtonNetwork[];
  taken: ButtonAction[];
  busy: boolean;
  onAdd: (a: ButtonAction) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const freePress = [1, 2, 3].filter((n) => !taken.some((a) => a.trigger === "press" && a.count === n));
  const freeHold = HOLDS.filter((s) => (!button.reserved || s < button.reserved) && !taken.some((a) => a.trigger === "hold" && a.seconds === s));
  const [trigger, setTrigger] = useState<"press" | "hold">(freePress.length > 0 ? "press" : "hold");
  const [count, setCount] = useState(freePress[0] ?? 1);
  const [seconds, setSeconds] = useState(freeHold[0] ?? 2);
  const [action, setAction] = useState<ButtonActionKind>(hasWifi ? "wifi_toggle" : "firewall_restart");
  const [iface, setIface] = useState(networks[0]?.section ?? "");
  const [minutes, setMinutes] = useState(30);

  const can = (trigger === "press" ? freePress.includes(count) : freeHold.includes(seconds))
    && (action !== "wifi_toggle" || iface !== "");

  const submit = () => {
    const a: ButtonAction = { button: button.name, trigger, action };
    if (trigger === "press") a.count = count; else a.seconds = seconds;
    if (action === "wifi_toggle") { a.iface = iface; a.minutes = minutes; }
    onAdd(a);
  };

  return (
    <div className="mt-2 rounded-md border border-border/60 p-3 flex flex-col gap-3">
      <SegmentedControl<"press" | "hold"> size="sm" value={trigger} onChange={setTrigger} ariaLabel={t("buttons.when")}
        options={[{ value: "press", label: t("buttons.trigPress") }, { value: "hold", label: t("buttons.trigHold") }]} />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {trigger === "press" ? (
          <Field label={t("buttons.presses")}>
            <select className={SELECT} value={count} onChange={(e) => setCount(Number(e.target.value))}>
              {[1, 2, 3].map((n) => <option key={n} value={n} disabled={!freePress.includes(n)}>{t(`buttons.press${n}`)}</option>)}
            </select>
          </Field>
        ) : (
          <Field label={t("buttons.holdFor")}
            hint={[t("buttons.holdHint"), button.reserved ? t("buttons.reservedHint", { count: button.reserved }) : ""].filter(Boolean).join(" ")}>
            <select className={SELECT} value={seconds} onChange={(e) => setSeconds(Number(e.target.value))}>
              {HOLDS.filter((s) => !button.reserved || s < button.reserved).map((s) => (
                <option key={s} value={s} disabled={!freeHold.includes(s)}>{t("buttons.hold", { count: s })}</option>
              ))}
            </select>
          </Field>
        )}
        <Field label={t("buttons.action")}>
          <select className={SELECT} value={action} onChange={(e) => setAction(e.target.value as ButtonActionKind)}>
            {ACTIONS.map((k) => (
              <option key={k} value={k} disabled={k === "wifi_toggle" && !hasWifi}>{t(`buttons.kind.${k}`)}</option>
            ))}
          </select>
        </Field>
        {action === "wifi_toggle" && (
          <>
            <Field label={t("buttons.network")} hint={networks.length === 0 ? t("buttons.noNetworks") : undefined}>
              <select className={SELECT} value={iface} onChange={(e) => setIface(e.target.value)}>
                {networks.map((n) => (
                  <option key={n.section} value={n.section}>
                    {(n.ssid || n.section) + (n.disabled ? ` (${t("buttons.netOff")})` : "")}
                  </option>
                ))}
              </select>
            </Field>
            <Field label={t("buttons.duration")} hint={t("buttons.durationHint")}>
              <select className={SELECT} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
                {DURATIONS.map((m) => <option key={m} value={m}>{minutesLabel(t, m)}</option>)}
              </select>
            </Field>
          </>
        )}
      </div>
      {action === "access_restart" && <p className="text-caption text-muted">{t("buttons.accessHint")}</p>}
      {action === "firewall_restart" && <p className="text-caption text-muted">{t("buttons.firewallHint")}</p>}
      <div className="flex gap-2">
        <Button size="sm" loading={busy} disabled={!can} onClick={submit}>{t("common.save")}</Button>
        <Button size="sm" variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
      </div>
    </div>
  );
}

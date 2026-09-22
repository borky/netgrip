import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Lock, ShieldCheck } from "lucide-react";
import { api } from "../../api";
import type { AccessProbe } from "../../types";
import { ActionBanner, Button, Card, Input, SegmentedControl, SkeletonRows, Toggle, useToast } from "../ui";
import { useActionCycle } from "../wifi/action";

// durationToMin convierte un time.Duration de Go ("12h0m0s") a minutos.
function durationToMin(d: string): number {
  if (!d) return 720;
  let total = 0;
  const re = /(\d+)([hms])/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(d)) !== null) {
    const n = Number(m[1]);
    if (m[2] === "h") total += n * 60;
    else if (m[2] === "m") total += n;
    else total += n / 60;
  }
  return Math.round(total) || 720;
}

/** Tres servicios distintos viven en esta tarjeta: el panel, LuCI y SSH.
 *  Cada uno guarda por su cuenta a propósito - con un botón común, apagar
 *  "forzar HTTPS" de LuCI reaplicaba también SSH y podía fallar con un error
 *  sobre dropbear, que no era lo que nadie había tocado. */
export function AccessCard({ index = 2 }: { index?: number }) {
  const { t } = useTranslation();
  const { push } = useToast();
  const [probe, setProbe] = useState<AccessProbe>();
  const [luciHttp, setLuciHttp] = useState(80);
  const [luciHttps, setLuciHttps] = useState(443);
  const [luciForce, setLuciForce] = useState(false);
  const [sshEnabled, setSshEnabled] = useState(true);
  const [sshPort, setSshPort] = useState("22");
  const [ttlMin, setTtlMin] = useState(720);
  const [hasCert, setHasCert] = useState(false);
  const [hasRouterCert, setHasRouterCert] = useState(false);
  // Lo aplicado, para saber al guardar si algo cambió de verdad: sólo
  // entonces hay que reiniciar el panel y llevarse el navegador con él.
  const [appliedHttps, setAppliedHttps] = useState(false);
  const [appliedCert, setAppliedCert] = useState<"panel" | "router">("panel");
  const [panelHttps, setPanelHttps] = useState(false);
  const [panelCert, setPanelCert] = useState<"panel" | "router">("panel");

  const panel = useActionCycle();
  const luci = useActionCycle();
  const ssh = useActionCycle();

  const reload = () => {
    api.access().then((p) => {
      setProbe(p);
      setLuciHttp(p.luci.http_port);
      setLuciHttps(p.luci.https_port);
      setLuciForce(p.luci.force_https);
      setSshEnabled(p.ssh.enabled);
      setSshPort(p.ssh.port || "22");
      setTtlMin(durationToMin(p.panel.session_ttl));
    }).catch(() => {});
    api.httpsState().then((s) => {
      setHasCert(s.has_cert);
      setHasRouterCert(s.router_cert);
      setPanelHttps(s.enabled);
      setAppliedHttps(s.enabled);
      setPanelCert(s.cert);
      setAppliedCert(s.cert);
    }).catch(() => {});
  };
  useEffect(reload, []);

  // Todo lo del panel se aplica aquí, al guardar. El interruptor de HTTPS
  // se aplicaba solo al pulsarlo, que es justo lo que un botón Guardar dice
  // que no va a pasar.
  const savePanel = () =>
    panel.run(async () => {
      await api.setPanelSessionTtl(ttlMin);
      const schemeChanged = panelHttps !== appliedHttps;
      const certChanged = panelHttps && panelCert !== appliedCert;
      if (!schemeChanged && !certChanged) return { status: "applied" as const };

      await api.setPanelHttps(panelHttps, panelCert);
      setAppliedHttps(panelHttps);
      setAppliedCert(panelCert);
      // Cambiar certificado sin cambiar de esquema también reinicia, pero
      // la URL no se mueve: basta con esperar a que vuelva.
      push({ tone: "ok", text: t("access.panelHttpsRestarting") });
      await waitForRestart();
      const target = `${panelHttps ? "https" : "http"}://${window.location.host}${window.location.pathname}`;
      window.setTimeout(() => { window.location.href = target; }, 800);
      return { status: "applied" as const };
    }).then(() => reload());

  const saveLuci = () =>
    luci.run(() =>
      api.setLuciAccess({ http_port: luciHttp, https_port: luciHttps, force_https: luciForce, enabled: true }),
    ).then((res) => { if (res?.status === "applied") reload(); });

  const saveSsh = () =>
    ssh.run(() => api.setSshAccess({ enabled: sshEnabled, port: sshPort })).then((res) => {
      if (res?.status === "applied") reload();
    });

  // Cambiar el esquema del propio panel obliga a reiniciarlo, así que la
  // pestaña que lo pidió se queda en una URL que ya no responde. Se avisa
  // antes y se lleva al usuario a la nueva, en vez de dejarlo mirando un
  // error de conexión.
  // El panel que responde es el que se va a reiniciar, así que no se puede
  // preguntar al nuevo si ya está: en el esquema viejo deja de responder y
  // en el nuevo la petición es de otro origen. Lo que sí se ve desde aquí es
  // que el viejo se cae; después de eso, procd lo ha relevado.
  const waitForRestart = async () => {
    const deadline = Date.now() + 15000;
    // Primero: que se caiga. Un temporizador fijo llegaba pronto y el
    // navegador pedía HTTP a un listener que aún era TLS, que responde
    // "Client sent an HTTP request to an HTTPS server".
    while (Date.now() < deadline) {
      try {
        await fetch(`/api/me?probe=${Date.now()}`, { cache: "no-store" });
      } catch {
        return; // dejó de responder: el proceso viejo se fue
      }
      await new Promise((r) => setTimeout(r, 300));
    }
  };


  const numPort = (value: number, onChange: (v: number) => void, ariaLabel: string) => (
    <Input
      type="number" mono min={1} max={65535} value={value || ""} aria-label={ariaLabel}
      onChange={(e) => onChange(Number(e.target.value))}
      className="w-24"
    />
  );

  const section = (title: string, body: React.ReactNode, save: () => void, cycle: ReturnType<typeof useActionCycle>, disabled?: boolean) => (
    <div className="flex flex-col gap-2 rounded-lg border border-border/60 p-3">
      <span className="text-small font-semibold uppercase tracking-wide text-muted">{title}</span>
      {body}
      <div className="flex items-center gap-3">
        <Button size="sm" onClick={save} loading={cycle.busy} disabled={disabled}>{t("access.save")}</Button>
        {cycle.phase && (
          <ActionBanner phase={cycle.phase} text={cycle.phase === "done" ? t("access.saved") : undefined}
            detail={cycle.detail} onDone={cycle.clear} />
        )}
      </div>
    </div>
  );

  return (
    <Card index={index} title={t("access.title")} icon={Lock}>
      {!probe ? (
        <SkeletonRows rows={3} />
      ) : (
        <div className="flex flex-col gap-3">
          <p className="text-caption text-muted">{t("access.disclaimer")}</p>

          {section(
            t("access.panelSection"),
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-3 py-1.5">
                <span className="text-body font-medium flex-1 min-w-0">{t("access.sessionTtl")}</span>
                <div className="flex items-center gap-1.5 shrink-0">
                  <Input type="number" mono min={1} max={100000} value={ttlMin || ""}
                    aria-label={t("access.sessionTtl")}
                    onChange={(e) => setTtlMin(Number(e.target.value))} className="w-20" />
                  <span className="text-small text-muted">{t("access.minutes")}</span>
                </div>
              </div>
              <div className="flex items-center gap-3 py-1.5">
                <div className="flex-1 min-w-0">
                  <span className="text-body font-medium">{t("access.panelHttps")}</span>
                  <p className="text-caption text-muted">{t("access.panelHttpsHint")}</p>
                </div>
                <Toggle checked={panelHttps} onChange={setPanelHttps} label={t("access.panelHttps")} />
              </div>
              {panelHttps && (
                <div className="flex flex-col gap-1.5 py-1.5">
                  <div className="flex items-center gap-3">
                    <span className="text-body font-medium flex-1 min-w-0">{t("access.certSource")}</span>
                    <SegmentedControl
                      size="sm"
                      ariaLabel={t("access.certSource")}
                      value={panelCert}
                      onChange={(v) => setPanelCert(v)}
                      options={
                        // La opción del router sólo aparece si ese par está:
                        // ofrecer algo que no se puede servir sería una
                        // promesa que el guardado rompe.
                        hasRouterCert
                          ? [
                              { value: "panel" as const, label: t("access.certOwn") },
                              { value: "router" as const, label: t("access.certRouter") },
                            ]
                          : [{ value: "panel" as const, label: t("access.certOwn") }]
                      }
                    />
                  </div>
                  <p className="text-caption text-muted">
                    {panelCert === "router" ? t("access.certRouterHint") : t("access.certOwnHint")}
                  </p>
                </div>
              )}
              <div className="flex items-center gap-2">
                <ShieldCheck size={14} className={hasCert ? "text-ok" : "text-faint"} aria-hidden="true" />
                <span className="text-small flex-1">{hasCert ? t("access.httpsReady") : t("access.httpsNone")}</span>
              </div>
            </div>,
            savePanel, panel, ttlMin <= 0,
          )}

          {section(
            t("access.luciSection"),
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-3 py-1.5">
                <span className="text-body font-medium flex-1 min-w-0">{t("access.luciPorts")}</span>
                <div className="flex items-center gap-1.5 shrink-0">
                  {numPort(luciHttp, setLuciHttp, t("access.luciHttp"))}
                  <span className="text-small text-muted">/</span>
                  {numPort(luciHttps, setLuciHttps, t("access.luciHttps"))}
                </div>
              </div>
              <div className="flex items-center gap-3 py-1.5">
                <span className="text-body font-medium flex-1">{t("access.forceHttps")}</span>
                <Toggle checked={luciForce} onChange={setLuciForce} label={t("access.forceHttps")} />
              </div>
            </div>,
            saveLuci, luci,
          )}

          {section(
            t("access.sshSection"),
            <div className="flex items-center gap-3 py-1.5">
              <div className="flex-1 min-w-0">
                <span className="text-body font-medium">{t("access.enableSsh")}</span>
                <p className="text-caption text-muted">{t("access.sshHint")}</p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <Input type="number" mono min={1} max={65535} value={sshPort}
                  aria-label={t("access.sshPort")} onChange={(e) => setSshPort(e.target.value)} className="w-20" />
                <Toggle checked={sshEnabled} onChange={setSshEnabled} label={t("access.enableSsh")} />
              </div>
            </div>,
            saveSsh, ssh,
          )}
        </div>
      )}
    </Card>
  );
}

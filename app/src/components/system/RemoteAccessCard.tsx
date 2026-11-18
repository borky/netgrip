import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Globe } from "lucide-react";
import { api } from "../../api";
import type { RemoteAccess } from "../../types";
import { Banner, Card, SettingRow, SkeletonRows, useToast } from "../ui";
import { AllowedFromChip, AllowedFromDialog, type AllowTarget } from "../ports/AllowLists";

type Key = "ping_wan" | "remote_https" | "remote_ssh";

export function RemoteAccessCard({ index = 1 }: { index?: number }) {
  const { t } = useTranslation();
  const { push } = useToast();
  const [probe, setProbe] = useState<RemoteAccess>();
  const [busy, setBusy] = useState<Key>();
  const [allowFor, setAllowFor] = useState<AllowTarget>();

  useEffect(() => {
    api.remoteAccess().then(setProbe).catch(() => {});
  }, []);

  const toggle = async (key: Key, value: boolean) => {
    setBusy(key);
    try {
      const res = await api.setRemoteAccess({ [key]: value });
      if (res.status !== "applied") {
        push({ tone: "danger", text: res.error || t("action.failed") });
      }
      setProbe(await api.remoteAccess());
    } catch (err) {
      push({ tone: "danger", text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(undefined);
    }
  };

  const items: { key: Key; label: string; hint: string }[] = [
    { key: "ping_wan", label: t("remote.pingWan"), hint: t("remote.pingWanHint") },
    { key: "remote_https", label: t("remote.https"), hint: t("remote.httpsHint") },
    { key: "remote_ssh", label: t("remote.ssh"), hint: t("remote.sshHint") },
  ];

  if (probe && !probe.applicable) {
    // modo AP: card atenuada con la razón
    return (
      <Card index={index} title={t("remote.title")} icon={Globe} iconTone="muted" className="opacity-70">
        <p className="text-small text-muted">{t("remote.notApplicable")}</p>
      </Card>
    );
  }

  // An open panel or SSH limited to an allow list is not "open to the
  // Internet" in the sense of the warning.
  const open = (on: boolean, af?: { kind: string }) => on && (!af || af.kind === "anyone");
  const exposed = !!probe && (open(probe.remote_https, probe.https_allowed) || open(probe.remote_ssh, probe.ssh_allowed));

  // Who may reach it, under a switch that is on.
  const allowRow = (key: Key) => {
    if (!probe) return null;
    const on = key === "remote_https" ? probe.remote_https : key === "remote_ssh" ? probe.remote_ssh : false;
    const af = key === "remote_https" ? probe.https_allowed : probe.ssh_allowed;
    const section = key === "remote_https" ? probe.https_section : probe.ssh_section;
    if (!on || !af || !section) return null;
    const label = key === "remote_https" ? t("remote.https") : t("remote.ssh");
    return (
      <div className="flex items-center gap-2 pb-3 -mt-1 text-caption text-muted">
        <span>{t("allow.allowedFrom")}</span>
        <AllowedFromChip af={af} onClick={() => setAllowFor({ section, label, current: af })} />
      </div>
    );
  };

  return (
    <Card index={index} title={t("remote.title")} icon={Globe}>
      {!probe ? (
        <SkeletonRows rows={3} />
      ) : (
        <div className="flex flex-col divide-y divide-border/60">
          {items.map((item) => (
            <div key={item.key}>
              <SettingRow
                title={item.label}
                description={item.hint}
                checked={probe[item.key]}
                busy={busy === item.key}
                onChange={(v) => toggle(item.key, v)}
              />
              {allowRow(item.key)}
            </div>
          ))}
          {exposed && (
            <div className="pt-3">
              <Banner tone="warn">{t("remote.warn")}</Banner>
            </div>
          )}
        </div>
      )}
      <AllowedFromDialog
        target={allowFor}
        onClose={() => setAllowFor(undefined)}
        onApplied={() => { api.remoteAccess().then(setProbe).catch(() => {}); }}
      />
    </Card>
  );
}

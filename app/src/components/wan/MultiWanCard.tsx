import { useTranslation } from "react-i18next";
import { Split } from "lucide-react";
import type { MultiWanProbe, WanCandidate } from "../../types";
import { Banner, Card, Pill, SkeletonRows, StatusDot } from "../ui";
import type { PillTone } from "../ui";

/** How long a link has been up, in the same shape the WAN card uses. */
function fmtDur(s: number): string {
  if (!s || s <= 0) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** The dot on the left: green carries traffic, amber is a healthy standby,
 *  red is down. A link that is up but routing nothing is not a fault. */
function dotTone(c: WanCandidate): "ok" | "warn" | "danger" {
  if (!c.up || c.online === "offline") return "danger";
  return c.active ? "ok" : "warn";
}

/** The one-word verdict. mwan3's opinion wins when it has one: it pings
 *  through the link, which is the difference between "the cable is in" and
 *  "this connection works". */
function stateLabel(c: WanCandidate): { key: string; tone: PillTone } {
  if (!c.up) return { key: "mwan.offline", tone: "danger" };
  if (c.online === "offline") return { key: "mwan.failed", tone: "danger" };
  if (c.active) return { key: "mwan.active", tone: "ok" };
  return { key: "mwan.standby", tone: "muted" };
}

function UplinkRow({ c }: { c: WanCandidate }) {
  const { t } = useTranslation();
  const state = stateLabel(c);
  const where = [c.proto, c.port ? t("mwan.viaPort", { port: c.port }) : ""].filter(Boolean).join(" · ");
  return (
    <div className="flex items-center gap-3 py-2.5 flex-wrap">
      <StatusDot tone={dotTone(c)} />
      <div className="min-w-0">
        <div className="text-body font-medium truncate">{c.name}</div>
        <div className="text-caption text-muted truncate">{where}</div>
      </div>
      <span className="font-mono text-caption bg-surface-2 border border-border rounded-sm px-1.5 py-0.5">
        {c.ipv4[0] ?? "—"}
      </span>
      <span className="flex-1" />
      {c.up && <span className="text-caption text-muted tabular-nums">{fmtDur(c.uptime)}</span>}
      {c.metered && <Pill tone="warn">{t("mwan.metered")}</Pill>}
      <Pill tone={state.tone}>
        {c.active && c.share_pct > 0 && c.share_pct < 100
          ? t("mwan.activeShare", { pct: c.share_pct })
          : t(state.key)}
      </Pill>
      {c.primary && <Pill tone="accent">{t("mwan.primary")}</Pill>}
    </div>
  );
}

/**
 * Card "Internet connections": every uplink the router has, which one is
 * carrying traffic, and — once there is more than one — what to do about it.
 *
 * Read-only for now: the mode controls arrive with the write path.
 */
export function MultiWanCard({ probe, index = 2 }: { probe?: MultiWanProbe; index?: number }) {
  const { t } = useTranslation();

  // On an access point there is no uplink to talk about at all.
  if (probe && !probe.applicable) return null;

  const modeKey: Record<string, string> = {
    failover: "mwan.modeFailover",
    balance: "mwan.modeBalance",
    custom: "mwan.modeCustom",
    off: "mwan.modeOff",
  };

  return (
    <Card
      index={index}
      icon={Split}
      title={t("mwan.title")}
      action={
        probe && probe.multi_wan_possible && probe.installed ? (
          <Pill tone={probe.mode === "custom" ? "warn" : probe.mode === "off" ? "muted" : "accent"}>
            {t(modeKey[probe.mode] ?? "mwan.modeOff")}
          </Pill>
        ) : undefined
      }
    >
      {!probe ? (
        <SkeletonRows rows={3} />
      ) : (
        <>
          <div className="divide-y divide-border/50">
            {probe.candidates.map((c) => (
              <UplinkRow key={c.name} c={c} />
            ))}
          </div>

          {/* One uplink: nothing to choose between, so say what a second
              one would buy rather than showing dead controls. */}
          {!probe.multi_wan_possible && (
            <p className="text-caption text-muted mt-2">{t("mwan.singleBody")}</p>
          )}

          {probe.multi_wan_possible && !probe.installed && (
            <Banner tone="info" className="mt-3">{t("mwan.installPrompt")}</Banner>
          )}

          {probe.multi_wan_possible && probe.installed && probe.foreign && (
            <Banner tone="warn" className="mt-3">
              {t("mwan.foreignBanner", { sections: probe.foreign_sections.join(", ") })}
            </Banner>
          )}
        </>
      )}
    </Card>
  );
}

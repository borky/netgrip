import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Globe, ListChecks, Pencil, Plus, ShieldCheck, Trash2, X } from "lucide-react";
import { api } from "../../api";
import type {
  AllowedFrom, AllowEntry, AllowExternal, AllowListView, AllowProbe, AllowResult, FwdRule,
} from "../../types";
import {
  Banner, Button, Card, ConfirmDialog, EmptyState, Field, Input, Modal, Pill, SkeletonRows, useToast,
} from "../ui";
import { RollbackConfirmModal, useRollbackConfirm } from "../rollback";

/* Allow lists: named lists of addresses, ranges and host names that a port
   open to the Internet can be limited to (modules/allowlists.go). */

const SELECT = "h-9 w-full rounded-sm border border-border bg-surface-2 px-2.5 text-small text-text outline-none focus:border-accent ring-focus";
const KEEP = [0, 1, 6, 24];

/** Short label of who may reach a port. */
export function allowedLabel(t: TFunction, af?: AllowedFrom): string {
  if (!af || af.kind === "anyone") return t("allow.anyone");
  if (af.kind === "list") return af.list_name || af.list || "";
  return af.negated ? t("allow.otherBlock", { set: af.set }) : t("allow.otherSet", { set: af.set });
}

/** The "Allowed from" chip of a port: opens the dialog to change it. */
export function AllowedFromChip({ af, onClick, disabled }: {
  af?: AllowedFrom;
  onClick: () => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation();
  const anyone = !af || af.kind === "anyone";
  const tone = anyone
    ? "border-warn/50 text-warn"
    : af?.kind === "list" ? "border-accent/50 text-accent" : "border-border text-muted";
  const Icon = anyone ? Globe : ShieldCheck;
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={t("allow.chipTitle")}
      className={`inline-flex items-center gap-1 max-w-56 rounded-sm border bg-surface-2 px-1.5 py-0.5 text-caption
        ring-focus hover:bg-surface transition-colors duration-[var(--dur-fast)] ${tone}`}
    >
      <Icon size={13} aria-hidden="true" className="shrink-0" />
      <span className="truncate">{allowedLabel(t, af)}</span>
      {af?.kind === "list" && af.families === "ipv4" && (
        <span className="text-faint shrink-0">· IPv4</span>
      )}
    </button>
  );
}

/** What a port is, for the dialog and the requests. */
export interface AllowTarget {
  section: string;
  label: string;
  rule?: FwdRule;
  current?: AllowedFrom;
}

/**
 * Dialog that sets who may reach one port: one of the lists, or anyone.
 * Keeps itself mounted for the revert window a change from outside arms.
 */
export function AllowedFromDialog({ target, onClose, onApplied }: {
  target?: AllowTarget;
  onClose: () => void;
  onApplied: () => void;
}) {
  const { t } = useTranslation();
  const { push } = useToast();
  const rc = useRollbackConfirm();
  const [probe, setProbe] = useState<AllowProbe>();
  const [choice, setChoice] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [ask, setAsk] = useState<{ reason: string; open?: boolean }>();

  useEffect(() => {
    if (!target) return;
    setError(undefined);
    setProbe(undefined);
    const cur = target.current;
    setChoice(cur?.kind === "list" ? cur.list ?? "" : cur?.kind === "other" ? "?" : "");
    api.allowlists().then(setProbe).catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [target]);

  const apply = async (force: boolean, open: boolean) => {
    if (!target) return;
    setBusy(true);
    setError(undefined);
    const r = target.rule;
    try {
      const res: AllowResult = await api.allowUse({
        section: target.section,
        list: choice,
        expect: r ? { name: r.name, port: r.src_dport, proto: r.proto, kind: r.kind ?? "" } : undefined,
        open_to_anyone: open,
        force,
      });
      if (res.status === "needs_force") {
        setAsk({ reason: res.error ?? "", open: choice === "" });
        return;
      }
      if (res.status !== "applied") {
        setError(res.error || t("action.failed"));
        onApplied();
        return;
      }
      push({ tone: "ok", text: t("allow.appliedFor", { name: target.label }) });
      rc.arm(res.confirm);
      onApplied();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const save = () => {
    if (choice === "") {
      // Removing a limit opens the port to everyone: always asked first.
      const cur = target?.current;
      if (cur && cur.kind !== "anyone") {
        setAsk({ reason: t("allow.openWarn", { name: target?.label }), open: true });
        return;
      }
    }
    apply(false, false);
  };

  const unchanged =
    (target?.current?.kind === "list" && choice === target.current.list) ||
    ((!target?.current || target.current.kind === "anyone") && choice === "") ||
    choice === "?";

  return (
    <>
      <Modal
        open={!!target}
        onClose={onClose}
        title={t("allow.dialogTitle", { name: target?.label ?? "" })}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
            <Button onClick={save} disabled={!probe || unchanged || busy} loading={busy}>{t("allow.apply")}</Button>
          </>
        }
      >
        {!probe ? (
          error ? <Banner tone="danger">{error}</Banner> : <SkeletonRows rows={3} />
        ) : !probe.supported ? (
          <Banner tone="warn">{probe.reason}</Banner>
        ) : (
          <div className="flex flex-col gap-2">
            <p className="text-small text-muted">{t("allow.dialogIntro")}</p>
            {target?.current?.kind === "other" && (
              <Banner tone="info">{t("allow.nowOther", { set: target.current.set })}</Banner>
            )}
            {probe.lists.length === 0 && (
              <Banner tone="info">{t("allow.noListsYet")}</Banner>
            )}
            {probe.lists.map((l) => (
              <ChoiceRow
                key={l.id}
                checked={choice === l.id}
                onSelect={() => setChoice(l.id)}
                title={l.name}
                icon={<ShieldCheck size={16} className="text-accent" aria-hidden="true" />}
                detail={listSummary(t, l)}
                badge={probe.you.lists.includes(l.id) ? <Pill tone="ok">{t("allow.includesYou")}</Pill> : undefined}
                warn={
                  target?.rule?.kind === "forward" && l.v4.length === 0
                    ? t("allow.noV4ForForward")
                    : l.v4.length === 0 && l.v6.length === 0 ? t("allow.emptyNobody") : undefined
                }
              />
            ))}
            <ChoiceRow
              checked={choice === ""}
              onSelect={() => setChoice("")}
              title={t("allow.anyoneLong")}
              icon={<Globe size={16} className="text-warn" aria-hidden="true" />}
              detail={t("allow.anyoneDetail")}
            />
            {!probe.you.local && (
              <p className="text-caption text-muted">{t("allow.youOutside", { ip: probe.you.ip })}</p>
            )}
            {error && <Banner tone="danger">{error}</Banner>}
          </div>
        )}
      </Modal>

      <ConfirmDialog
        open={!!ask}
        onClose={() => setAsk(undefined)}
        onConfirm={() => { const a = ask; setAsk(undefined); if (a) apply(true, !!a.open); }}
        title={ask?.open ? t("allow.openTitle", { name: target?.label ?? "" }) : t("allow.forceTitle")}
        consequence={ask?.reason ?? ""}
        confirmLabel={ask?.open ? t("allow.openConfirm") : t("allow.forceConfirm")}
        busy={busy}
      />
      <RollbackConfirmModal
        pending={rc.pending}
        seconds={rc.seconds}
        onKeep={() => { rc.keep(); onApplied(); }}
        onRevert={() => { rc.revert(); setTimeout(onApplied, 3000); }}
      />
    </>
  );
}

function ChoiceRow({ checked, onSelect, title, icon, detail, badge, warn }: {
  checked: boolean;
  onSelect: () => void;
  title: string;
  icon: React.ReactNode;
  detail?: string;
  badge?: React.ReactNode;
  warn?: string;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={checked}
      onClick={onSelect}
      className={`flex items-start gap-2.5 rounded-md border p-2.5 text-left ring-focus transition-colors duration-[var(--dur-fast)]
        ${checked ? "border-accent bg-accent-soft" : "border-border bg-surface-2 hover:bg-surface"}`}
    >
      <span className="mt-0.5 shrink-0">{icon}</span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2 flex-wrap">
          <span className="text-small font-medium break-words">{title}</span>
          {badge}
        </span>
        {detail && <span className="block text-caption text-muted break-words">{detail}</span>}
        {warn && <span className="block text-caption text-warn">{warn}</span>}
      </span>
    </button>
  );
}

function listSummary(t: TFunction, l: AllowListView): string {
  const parts = l.entries.slice(0, 3).map((e) => e.value);
  const more = l.entries.length > 3 ? ` ${t("allow.andMore", { count: l.entries.length - 3 })}` : "";
  return l.entries.length === 0 ? t("allow.emptyList") : parts.join(", ") + more;
}

/* ══════════ The card ══════════ */

export function AllowListsCard({ index = 1, rev = 0, onChanged }: {
  index?: number;
  /** Bumped by the page when a port's list changed elsewhere: reload. */
  rev?: number;
  onChanged?: () => void;
}) {
  const { t } = useTranslation();
  const { push } = useToast();
  const [probe, setProbe] = useState<AllowProbe>();
  const [edit, setEdit] = useState<AllowListView | "new">();
  const [del, setDel] = useState<AllowListView>();
  const [takeover, setTakeover] = useState<AllowExternal>();
  const [busy, setBusy] = useState(false);

  const load = () => api.allowlists().then(setProbe).catch(() => {});
  useEffect(() => { load(); }, [rev]);

  const changed = (p?: AllowProbe) => {
    if (p) setProbe(p); else load();
    onChanged?.();
  };

  const remove = async (l: AllowListView) => {
    setBusy(true);
    try {
      const res = await api.deleteAllowlist(l.id);
      if (res.status !== "applied") push({ tone: "danger", text: res.error || t("action.failed") });
      changed(res.state);
    } finally {
      setBusy(false);
    }
  };

  const full = !!probe && probe.lists.length >= probe.max_lists;

  return (
    <>
      <Card
        index={index}
        icon={ListChecks}
        iconTone="ok"
        title={t("allow.title")}
        help="allowlists"
        action={probe?.supported && (
          <Button size="sm" icon={Plus} onClick={() => setEdit("new")} disabled={full}>{t("allow.newList")}</Button>
        )}
      >
        {!probe ? (
          <SkeletonRows rows={3} />
        ) : !probe.supported ? (
          <Banner tone="warn">{probe.reason}</Banner>
        ) : (
          <div className="flex flex-col gap-3">
            <p className="text-small text-muted">{t("allow.intro")}</p>
            {!probe.you.local && (
              <Banner tone="info">
                {probe.you.lists.length > 0
                  ? t("allow.youOutsideIn", {
                    ip: probe.you.ip,
                    lists: probe.lists.filter((l) => probe.you.lists.includes(l.id)).map((l) => l.name).join(", "),
                  })
                  : t("allow.youOutsideNone", { ip: probe.you.ip })}
              </Banner>
            )}
            {probe.lists.length === 0 ? (
              <EmptyState
                title={t("allow.emptyHero")}
                action={<Button icon={Plus} onClick={() => setEdit("new")}>{t("allow.firstList")}</Button>}
              />
            ) : (
              <div className="divide-y divide-border/50">
                {probe.lists.map((l) => (
                  <ListRow key={l.id} l={l} busy={busy} onEdit={() => setEdit(l)} onDelete={() => setDel(l)} />
                ))}
              </div>
            )}

            {probe.external.length > 0 && (
              <div className="mt-2">
                <p className="text-eyebrow text-faint mb-2">{t("allow.externalTitle")}</p>
                <div className="divide-y divide-border/50">
                  {probe.external.map((e) => (
                    <ExternalRow key={e.set} e={e} onTakeOver={() => setTakeover(e)} disabled={!probe.you.local} />
                  ))}
                </div>
                {!probe.you.local && probe.external.some((e) => e.can_take_over) && (
                  <p className="text-caption text-muted mt-1">{t("allow.takeoverLocalOnly")}</p>
                )}
              </div>
            )}
          </div>
        )}
      </Card>

      <ListEditor
        open={edit !== undefined}
        list={edit === "new" ? undefined : edit}
        maxEntries={probe?.max_entries ?? 64}
        onClose={() => setEdit(undefined)}
        onSaved={(p) => { setEdit(undefined); changed(p); }}
      />
      <TakeoverDialog
        ext={takeover}
        maxEntries={probe?.max_entries ?? 64}
        onClose={() => setTakeover(undefined)}
        onDone={(p) => { setTakeover(undefined); changed(p); }}
      />
      <ConfirmDialog
        open={!!del}
        onClose={() => setDel(undefined)}
        onConfirm={() => { const l = del; setDel(undefined); if (l) remove(l); }}
        title={t("allow.deleteTitle", { name: del?.name ?? "" })}
        consequence={t("allow.deleteConsequence")}
        confirmLabel={t("allow.deleteConfirm")}
        busy={busy}
      />
    </>
  );
}

function ListRow({ l, busy, onEdit, onDelete }: {
  l: AllowListView;
  busy: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const used = l.used_by.length > 0;
  return (
    <div className="py-3 animate-fade-up">
      <div className="flex items-center gap-2 flex-wrap">
        <ShieldCheck size={16} className="text-accent shrink-0" aria-hidden="true" />
        <span className="text-body font-medium min-w-0 break-words">{l.name}</span>
        <Pill tone="muted">{t("allow.entries", { count: l.entries.length })}</Pill>
        {used
          ? <Pill tone="accent">{t("allow.usedBy", { names: l.used_by.map((r) => r.name || `:${r.src_dport}`).join(", ") })}</Pill>
          : <Pill tone="muted">{t("allow.notUsed")}</Pill>}
        <span className="flex-1" />
        <button type="button" onClick={onEdit} disabled={busy} aria-label={`${t("allow.edit")} ${l.name}`}
          className="text-faint hover:text-text transition-colors duration-[var(--dur-fast)] ring-focus rounded-sm p-1">
          <Pencil size={16} />
        </button>
        <button type="button" onClick={onDelete} disabled={busy || used}
          title={used ? t("allow.deleteInUse") : undefined}
          aria-label={`${t("allow.delete")} ${l.name}`}
          className="text-faint hover:text-danger disabled:opacity-40 disabled:hover:text-faint transition-colors duration-[var(--dur-fast)] ring-focus rounded-sm p-1">
          <Trash2 size={16} />
        </button>
      </div>
      {l.entries.length === 0 ? (
        <p className="text-caption text-warn mt-1 ml-6">{t("allow.emptyNobody")}</p>
      ) : (
        <ul className="mt-1.5 ml-6 flex flex-col gap-1">
          {l.entries.map((e) => (
            <li key={e.value} className="text-small min-w-0">
              <span className="font-mono break-all">{e.value}</span>
              {e.note && <span className="text-muted"> · {e.note}</span>}
              {e.kind === "host" && (
                <span className="block text-caption">
                  {e.addresses.length > 0 && (
                    <span className="text-muted font-mono break-all">→ {e.addresses.join(", ")}</span>
                  )}
                  {e.stale && <span className="text-warn"> · {t("allow.stale")}</span>}
                  {e.error && !e.stale && <span className="text-danger">{e.addresses.length > 0 ? " · " : ""}{e.error}</span>}
                  {!e.error && e.addresses.length === 0 && <span className="text-faint">{t("allow.notLookedUp")}</span>}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ExternalRow({ e, onTakeOver, disabled }: { e: AllowExternal; onTakeOver: () => void; disabled: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="py-2.5">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-mono text-small">{e.set}</span>
        <Pill tone="muted">{t("allow.addresses", { count: e.elements.length })}</Pill>
        {e.used_by.length > 0 && (
          <Pill tone="muted">{t("allow.usedBy", { names: e.used_by.map((r) => r.name || `:${r.src_dport}`).join(", ") })}</Pill>
        )}
        <span className="flex-1" />
        {e.can_take_over
          ? <Button size="sm" variant="ghost" onClick={onTakeOver} disabled={disabled}>{t("allow.takeover")}</Button>
          : <span className="text-caption text-faint">{t("allow.cannotTakeOver", { why: e.why })}</span>}
      </div>
      {e.writers.length > 0 && (
        <p className="text-caption text-muted mt-1">
          {t("allow.filledBy")} <span className="font-mono break-all">{e.writers.join(" · ")}</span>
        </p>
      )}
    </div>
  );
}

/* ══════════ Entries editor ══════════ */

interface Row { value: string; note: string }

const hostRe = /^(?=.{1,253}\.?$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]*[a-z][a-z0-9-]*\.?$/i;
const v4Re = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const v6Re = /^[0-9a-f:.]+(\/\d{1,3})?$/i;

/** A rough check while typing; the router has the last word. */
function looksValid(v: string): boolean {
  v = v.trim();
  if (!v) return true;
  if (v4Re.test(v)) return v.split("/")[0].split(".").every((n) => Number(n) <= 255);
  if (v.includes(":")) return v6Re.test(v);
  return hostRe.test(v);
}

function EntriesEditor({ rows, setRows, max }: { rows: Row[]; setRows: (r: Row[]) => void; max: number }) {
  const { t } = useTranslation();
  const update = (i: number, r: Partial<Row>) => setRows(rows.map((x, j) => (j === i ? { ...x, ...r } : x)));
  // Pasting several addresses at once (one per line, or separated by
  // commas or spaces) makes one row each.
  const paste = (i: number, text: string) => {
    const parts = text.split(/[\s,;]+/).map((p) => p.trim()).filter(Boolean);
    if (parts.length < 2) return false;
    const next = [...rows];
    next.splice(i, 1, ...parts.map((p) => ({ value: p, note: "" })));
    setRows(next.slice(0, max));
    return true;
  };
  return (
    <div className="flex flex-col gap-2">
      {rows.map((r, i) => (
        <div key={i} className="flex items-start gap-2">
          {/* Side by side on wide screens, the note under the address on a
              phone. */}
          <div className="flex-1 min-w-0 flex flex-col sm:flex-row gap-1.5 sm:gap-2">
          <div className="sm:flex-[3] min-w-0">
            <Input
              mono
              value={r.value}
              onChange={(e) => update(i, { value: e.target.value })}
              onPaste={(e) => { if (paste(i, e.clipboardData.getData("text"))) e.preventDefault(); }}
              placeholder={t("allow.entryPlaceholder")}
              aria-label={t("allow.entryLabel")}
              error={!looksValid(r.value)}
            />
          </div>
          <div className="sm:flex-[2] min-w-0">
            <Input
              value={r.note}
              onChange={(e) => update(i, { note: e.target.value })}
              placeholder={t("allow.notePlaceholder")}
              aria-label={t("allow.noteLabel")}
              maxLength={64}
            />
          </div>
          </div>
          <button type="button" onClick={() => setRows(rows.filter((_, j) => j !== i))}
            aria-label={t("allow.removeEntry")}
            className="mt-2 text-faint hover:text-danger transition-colors duration-[var(--dur-fast)] ring-focus rounded-sm p-1">
            <X size={16} />
          </button>
        </div>
      ))}
      <div>
        <Button size="sm" variant="ghost" icon={Plus} disabled={rows.length >= max}
          onClick={() => setRows([...rows, { value: "", note: "" }])}>
          {t("allow.addEntry")}
        </Button>
      </div>
      <p className="text-caption text-muted">{t("allow.entryHint")}</p>
    </div>
  );
}

function KeepSelect({ value, onChange }: { value: number; onChange: (v: number) => void }) {
  const { t } = useTranslation();
  return (
    <label className="block">
      <span className="mb-1.5 block text-caption font-medium text-muted">{t("allow.keepLabel")}</span>
      <select className={SELECT} value={value} onChange={(e) => onChange(Number(e.target.value))}>
        {KEEP.map((h) => (
          <option key={h} value={h}>{h === 0 ? t("allow.keepNone") : t("allow.keepHours", { count: h })}</option>
        ))}
      </select>
      <span className="mt-1 block text-caption text-faint">{t("allow.keepHint")}</span>
    </label>
  );
}

const toRows = (es?: AllowEntry[]): Row[] => (es ?? []).map((e) => ({ value: e.value, note: e.note ?? "" }));
const toEntries = (rows: Row[]): AllowEntry[] =>
  rows.filter((r) => r.value.trim()).map((r) => ({ value: r.value.trim(), note: r.note.trim() || undefined }));

/* ══════════ New / edit list ══════════ */

function ListEditor({ open, list, maxEntries, onClose, onSaved }: {
  open: boolean;
  list?: AllowListView;
  maxEntries: number;
  onClose: () => void;
  onSaved: (p?: AllowProbe) => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [keep, setKeep] = useState(24);
  const [rows, setRows] = useState<Row[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [ask, setAsk] = useState<string>();

  useEffect(() => {
    if (!open) return;
    setName(list?.name ?? "");
    setKeep(list?.keep_hours ?? 24);
    setRows(list ? toRows(list.entries) : [{ value: "", note: "" }]);
    setError(undefined);
  }, [open, list]);

  const save = async (force: boolean) => {
    setBusy(true);
    setError(undefined);
    try {
      const res = await api.saveAllowlist({ id: list?.id, name, keep_hours: keep, entries: toEntries(rows), force });
      if (res.status === "needs_force") { setAsk(res.error); return; }
      if (res.status !== "applied") { setError(res.error || t("action.failed")); return; }
      onSaved(res.state);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const valid = name.trim() !== "" && rows.every((r) => looksValid(r.value));
  return (
    <>
      <Modal open={open} onClose={onClose} wide title={list ? t("allow.editTitle", { name: list.name }) : t("allow.newTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
            <Button onClick={() => save(false)} disabled={!valid || busy} loading={busy}>{t("allow.save")}</Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Field label={t("allow.nameLabel")}
            inputProps={{ value: name, onChange: (e) => setName(e.target.value), maxLength: 40, placeholder: t("allow.namePlaceholder") }} />
          <div>
            <p className="text-caption font-medium text-muted mb-1.5">{t("allow.entriesLabel")}</p>
            <EntriesEditor rows={rows} setRows={setRows} max={maxEntries} />
          </div>
          <KeepSelect value={keep} onChange={setKeep} />
          {toEntries(rows).length === 0 && <Banner tone="warn">{t("allow.emptyNobody")}</Banner>}
          {error && <Banner tone="danger">{error}</Banner>}
        </div>
      </Modal>
      <ConfirmDialog
        open={!!ask}
        onClose={() => setAsk(undefined)}
        onConfirm={() => { setAsk(undefined); save(true); }}
        title={t("allow.forceTitle")}
        consequence={ask ?? ""}
        confirmLabel={t("allow.forceConfirm")}
        busy={busy}
      />
    </>
  );
}

/* ══════════ Take over a set managed elsewhere ══════════ */

function TakeoverDialog({ ext, maxEntries, onClose, onDone }: {
  ext?: AllowExternal;
  maxEntries: number;
  onClose: () => void;
  onDone: (p?: AllowProbe) => void;
}) {
  const { t } = useTranslation();
  const { push } = useToast();
  const [info, setInfo] = useState<AllowExternal>();
  const [name, setName] = useState("");
  const [keep, setKeep] = useState(24);
  const [rows, setRows] = useState<Row[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [ask, setAsk] = useState<string>();

  useEffect(() => {
    if (!ext) return;
    setInfo(undefined);
    setError(undefined);
    setName(ext.set.replace(/[_-]+/g, " ").replace(/^./, (c) => c.toUpperCase()));
    setKeep(24);
    api.allowTakeoverInfo(ext.set)
      .then((i) => { setInfo(i); setRows(toRows(i.suggest)); })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [ext]);

  const go = async (force: boolean) => {
    if (!ext) return;
    setBusy(true);
    setError(undefined);
    try {
      const res = await api.allowTakeover({ set: ext.set, name, keep_hours: keep, entries: toEntries(rows), force });
      if (res.status === "needs_force") { setAsk(res.error); return; }
      if (res.status !== "applied") { setError(res.error || t("action.failed")); return; }
      push({ tone: "ok", text: t("allow.takenOver", { set: ext.set, name }) });
      onDone(res.state);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const valid = name.trim() !== "" && rows.every((r) => looksValid(r.value));
  return (
    <>
      <Modal open={!!ext} onClose={onClose} wide title={t("allow.takeoverTitle", { set: ext?.set ?? "" })}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
            <Button onClick={() => go(false)} disabled={!info || !valid || busy} loading={busy}>{t("allow.takeover")}</Button>
          </>
        }
      >
        {!info ? (
          error ? <Banner tone="danger">{error}</Banner> : <SkeletonRows rows={4} />
        ) : (
          <div className="flex flex-col gap-4">
            <p className="text-small text-muted">{t("allow.takeoverIntro", { set: info.set })}</p>
            <ul className="text-small list-disc ml-5 flex flex-col gap-1">
              <li>{t("allow.takeoverPorts", { names: info.used_by.map((r) => r.name || `:${r.src_dport}`).join(", ") })}</li>
              <li>{t("allow.takeoverNow", { addrs: info.elements.join(", ") || "—" })}</li>
              {info.writers.length > 0 && (
                <li>
                  {t("allow.takeoverJobs")}{" "}
                  <span className="font-mono text-caption break-all">{info.writers.join(" · ")}</span>
                </li>
              )}
            </ul>
            <Field label={t("allow.nameLabel")}
              inputProps={{ value: name, onChange: (e) => setName(e.target.value), maxLength: 40 }} />
            <div>
              <p className="text-caption font-medium text-muted mb-1.5">{t("allow.entriesLabel")}</p>
              <EntriesEditor rows={rows} setRows={setRows} max={maxEntries} />
            </div>
            <KeepSelect value={keep} onChange={setKeep} />
            {error && <Banner tone="danger">{error}</Banner>}
          </div>
        )}
      </Modal>
      <ConfirmDialog
        open={!!ask}
        onClose={() => setAsk(undefined)}
        onConfirm={() => { setAsk(undefined); go(true); }}
        title={t("allow.forceTitle")}
        consequence={ask ?? ""}
        confirmLabel={t("allow.forceConfirm")}
        busy={busy}
      />
    </>
  );
}

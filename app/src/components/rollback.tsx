import { useEffect, useState } from "react";
import { Clock } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { Button, IconTile, Modal, useToast } from "./ui";

export interface PendingConfirm {
  id: string;
  expires: number;
}

/**
 * Rollback-confirm window for connectivity-risky saves (LAN, WAN, WiFi,
 * firewall). The server auto-reverts unless the UI confirms it can still
 * reach the panel; `arm` opens the window from a save response, `keep` and
 * `revert` close it. Re-hydrates from the server on mount so a page reload
 * does not strand a pending window.
 */
export function useRollbackConfirm() {
  const { t } = useTranslation();
  const { push } = useToast();
  const [pending, setPending] = useState<PendingConfirm | null>(null);
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    api.confirmStatus()
      .then((c) => { if (c?.pending && c.id && c.expires) setPending({ id: c.id, expires: c.expires }); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!pending) return;
    const tick = () => {
      const left = Math.max(0, Math.ceil(pending.expires - Date.now() / 1000));
      setSeconds(left);
      if (left <= 0) {
        setPending(null);
        // The server reverts on its own at expiry; ask how that went a
        // moment later instead of assuming it worked.
        setTimeout(() => {
          api.confirmStatus()
            .then((c) => {
              const lr = c?.last_revert;
              if (lr && !lr.ok && lr.at >= pending.expires - 5) {
                push({ tone: "danger", text: t("common.rollbackFailed", { error: lr.error ?? "" }) });
              }
            })
            .catch(() => {});
        }, 5000);
      }
    };
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending]);

  const keep = () => {
    const id = pending?.id;
    setPending(null);
    if (id) api.confirmKeep(id).catch(() => {});
  };

  const revert = () => {
    const id = pending?.id;
    setPending(null);
    if (id) {
      api.confirmRevert(id).catch((e) => {
        push({ tone: "danger", text: t("common.rollbackFailed", { error: e instanceof Error ? e.message : String(e) }) });
      });
    }
  };

  const arm = (confirm?: { id: string; expires: number }) => {
    if (confirm) setPending(confirm);
  };

  return { pending, seconds, keep, revert, arm };
}

export function RollbackConfirmModal({ pending, seconds, onKeep, onRevert }: {
  pending: PendingConfirm | null;
  seconds: number;
  onKeep: () => void;
  onRevert: () => void;
}) {
  const { t } = useTranslation();
  return (
    <Modal open={pending !== null} onClose={onKeep}>
      <div className="flex items-start gap-3">
        <IconTile icon={Clock} tone="accent" />
        <div className="min-w-0">
          <h2 className="text-h2">{t("common.rollbackTitle")}</h2>
          <p className="text-small text-muted mt-1">{t("common.rollbackBody", { seconds })}</p>
        </div>
      </div>
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="danger" onClick={onRevert}>{t("common.revert")}</Button>
        <Button onClick={onKeep}>{t("common.keep")}</Button>
      </div>
    </Modal>
  );
}

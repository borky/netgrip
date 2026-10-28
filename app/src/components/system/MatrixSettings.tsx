import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Bell, Hash, KeyRound, Server } from "lucide-react";
import { api } from "../../api";
import { Button, Field, SettingRow, useToast } from "../ui";

/**
 * Matrix block inside "Alerts and integrations", next to Telegram and ntfy.
 * No Card of its own: CollapsibleSection wraps it. `onStatus` tells the
 * parent once loaded so it can paint the status pill. The router checks the
 * token and the room membership before it saves, and stores all three
 * values encrypted; the token is write-only.
 */
export function MatrixSettings({ onStatus }: { onStatus?: (enabled: boolean) => void }) {
  const { t } = useTranslation();
  const { push } = useToast();
  const [server, setServer] = useState("");
  const [roomId, setRoomId] = useState("");
  const [token, setToken] = useState("");
  const [tokenSet, setTokenSet] = useState(false);
  const [unreadable, setUnreadable] = useState(false);
  const [enabled, setEnabled] = useState(false);
  // What the router has stored: the status pill and Test follow this, not
  // the switch before it is saved.
  const [savedEnabled, setSavedEnabled] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    api.matrixGet().then((d) => {
      setServer(d.server || "");
      setRoomId(d.roomId || "");
      setTokenSet(d.tokenSet);
      setUnreadable(d.unreadable);
      setEnabled(d.enabled);
      setSavedEnabled(d.enabled);
      onStatus?.(d.enabled);
    }).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      await api.matrixSet(server, roomId, token, enabled);
      if (token) setTokenSet(true);
      setToken("");
      setUnreadable(false);
      setSavedEnabled(enabled);
      push({ tone: "ok", text: t("matrix.saved") });
      onStatus?.(enabled);
    } catch (e) {
      push({ tone: "danger", text: e instanceof Error ? e.message : String(e) });
    }
    setSaving(false);
  };

  const test = async () => {
    setTesting(true);
    try {
      await api.matrixTest();
      push({ tone: "ok", text: t("matrix.testSent") });
    } catch (e) {
      push({ tone: "danger", text: e instanceof Error ? e.message : String(e) });
    }
    setTesting(false);
  };

  // Saving switched off is always allowed: it is how a channel whose stored
  // credentials cannot be read gets cleared.
  const complete = server !== "" && roomId !== "" && (tokenSet || token !== "");

  return (
    <>
      {unreadable && <p className="mb-2 text-xs text-warn">{t("matrix.unreadable")}</p>}
      <SettingRow
        title={t("matrix.enabled")}
        description={t("matrix.description")}
        checked={enabled}
        onChange={setEnabled}
      />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-1">
        <Field
          label={t("matrix.server")}
          icon={Server}
          helpTitle={t("help.matrix.title")}
          help={t("help.matrix.body")}
          inputProps={{
            mono: true, value: server,
            onChange: (e) => setServer(e.target.value),
            placeholder: "https://matrix.example.org",
          }}
        />
        <Field
          label={t("matrix.roomId")}
          icon={Hash}
          inputProps={{
            mono: true, value: roomId,
            onChange: (e) => setRoomId(e.target.value),
            placeholder: "!AbCdEfGhIjKlMnOp",
          }}
        />
        <Field
          label={t("matrix.token")}
          icon={KeyRound}
          hint={tokenSet ? t("matrix.tokenSet") : undefined}
          inputProps={{
            type: "password", mono: true, value: token,
            onChange: (e) => setToken(e.target.value),
            placeholder: tokenSet ? "••••••••" : "syt_…",
          }}
        />
      </div>
      <div className="flex gap-2 mt-3">
        <Button size="sm" onClick={save} loading={saving} disabled={!complete && enabled}>
          {t("matrix.save")}
        </Button>
        <Button size="sm" variant="secondary" icon={Bell} onClick={test} loading={testing} disabled={!savedEnabled || !tokenSet}>
          {t("matrix.sendTest")}
        </Button>
      </div>
    </>
  );
}

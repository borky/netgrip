import { useState } from "react";
import type { FwdProbe } from "../types";
import { api } from "../api";
import { PortForwardCard } from "../components/ports/PortForwardCard";
import { AllowListsCard } from "../components/ports/AllowLists";

/**
 * Puertos (#353): apertura de puertos a Internet. Vive como entrada propia
 * del menú ("Puertos") junto a "Puertos ethernet"; antes era una tarjeta al
 * final de la página WAN.
 */
export function ForwardsPage({ fwd, onFwdChange }: {
  fwd?: FwdProbe;
  onFwdChange: (p: FwdProbe) => void;
}) {
  // Bumped when a port's allow list changes, so the lists card reloads
  // (who uses which list) and the other way round.
  const [allowRev, setAllowRev] = useState(0);
  return (
    <div className="flex flex-col gap-[var(--card-gap)]">
      <PortForwardCard probe={fwd} onChange={onFwdChange} onAllowChanged={() => setAllowRev((n) => n + 1)} />
      <AllowListsCard
        rev={allowRev}
        index={1}
        onChanged={() => { api.portforward().then(onFwdChange).catch(() => {}); }}
      />
    </div>
  );
}

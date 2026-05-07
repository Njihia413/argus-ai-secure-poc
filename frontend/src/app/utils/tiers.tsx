export type Tier = "none" | "key_unbound" | "key_bound";

export const TIER_VALUES: Tier[] = ["none", "key_unbound", "key_bound"];

export const tierLabel: Record<Tier, string> = {
  none: "no key needed",
  key_unbound: "key required",
  key_bound: "key + bound machine",
};

export const tierTone: Record<Tier, string> = {
  none: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20",
  key_unbound: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20",
  key_bound: "bg-sky-500/10 text-sky-700 dark:text-sky-400 border-sky-500/20",
};

export function TierPill({ tier }: { tier: Tier }) {
  return (
    <span
      className={`text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-md border ${tierTone[tier]}`}
    >
      {tierLabel[tier]}
    </span>
  );
}

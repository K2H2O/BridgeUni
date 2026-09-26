/** BridgeUni wordmark: a bridge arc in a rounded square. */
export function Logo({ inverted = false }: { inverted?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <svg viewBox="0 0 32 32" className="size-8 shrink-0" aria-hidden>
        <rect width="32" height="32" rx="8" fill={inverted ? "var(--primary-foreground)" : "var(--primary)"} />
        <path
          d="M6 22V17c3-5 7-7.5 10-7.5S23 12 26 17v5M6 17h20M11 13v9M16 10v12M21 13v9"
          fill="none"
          stroke={inverted ? "var(--primary)" : "var(--primary-foreground)"}
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className={`font-display text-xl font-extrabold tracking-tight ${inverted ? "text-primary-foreground" : "text-foreground"}`}>
        Bridge<span className={inverted ? "text-accent" : "text-primary"}>Uni</span>
      </span>
    </span>
  );
}

import { cn } from "@/lib/utils";

/**
 * Sentinel mark — a geometric shield with a vigilance bar + watch-dot.
 * Single-color (currentColor), crisp at any size. No raster, no gradients.
 */
export function SentinelMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className={cn("shrink-0", className)}>
      <path
        d="M12 1.75 19.25 4.4v5.95c0 4.78-3.06 8.2-7.25 9.9-4.19-1.7-7.25-5.12-7.25-9.9V4.4L12 1.75Z"
        fill="currentColor"
        fillOpacity="0.1"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path d="M12 6.4v6.3" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      <circle cx="12" cy="15.6" r="1.08" fill="currentColor" />
    </svg>
  );
}

export function Wordmark({ className, markClass }: { className?: string; markClass?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <SentinelMark className={cn("size-7 text-primary", markClass)} />
      <span className="font-mono text-[15px] font-semibold tracking-[0.34em]">SENTINEL</span>
    </span>
  );
}

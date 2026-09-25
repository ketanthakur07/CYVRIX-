import { cn } from "@/lib/cn";
import type { StateTone } from "@/lib/workflow";

const TONE_STYLES: Record<StateTone, string> = {
  neutral: "bg-gray-100 text-gray-700 border-gray-200",
  info: "bg-blue-100 text-blue-800 border-blue-200",
  success: "bg-green-100 text-green-800 border-green-200",
  warning: "bg-amber-100 text-amber-800 border-amber-200",
  danger: "bg-red-100 text-red-800 border-red-200",
  pending: "bg-yellow-100 text-yellow-800 border-yellow-200",
};

export function Badge({
  children,
  tone = "neutral",
  className,
  title,
}: {
  children: React.ReactNode;
  tone?: StateTone;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium whitespace-nowrap",
        TONE_STYLES[tone],
        className
      )}
    >
      {children}
    </span>
  );
}

/**
 * Status word badge. Renders an unknown backend state verbatim (never
 * crashes, never coerces) so the UI always tells the truth about what
 * the server said.
 */
export function StateBadge({
  state,
  tone,
  label,
}: {
  state: string | null | undefined;
  tone: StateTone;
  label?: string;
}) {
  return <Badge tone={tone}>{label ?? state ?? "—"}</Badge>;
}

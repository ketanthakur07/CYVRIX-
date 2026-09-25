import { cn } from "@/lib/cn";

type Variant = "primary" | "secondary" | "danger" | "ghost";

const VARIANT_STYLES: Record<Variant, string> = {
  primary: "bg-blue-600 text-white hover:bg-blue-700 border-blue-600",
  secondary: "bg-white text-gray-700 hover:bg-gray-50 border-gray-300",
  danger: "bg-red-600 text-white hover:bg-red-700 border-red-600",
  ghost: "bg-transparent text-gray-600 hover:bg-gray-100 border-transparent",
};

/**
 * Shared button. `pending` renders an in-flight label and disables the
 * control. Disabling is a UX guard only — the server rejects duplicate or
 * unauthorized submissions independently.
 */
export function Button({
  children,
  variant = "primary",
  type = "button",
  disabled,
  pending,
  pendingLabel = "Working…",
  onClick,
  className,
  title,
}: {
  children: React.ReactNode;
  variant?: Variant;
  type?: "button" | "submit";
  disabled?: boolean;
  pending?: boolean;
  pendingLabel?: string;
  onClick?: () => void;
  className?: string;
  title?: string;
}) {
  const isDisabled = disabled || pending;
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={isDisabled}
      title={title}
      aria-busy={pending || undefined}
      className={cn(
        "inline-flex items-center justify-center gap-2 px-4 py-2 rounded border text-sm font-medium transition-colors",
        "disabled:opacity-40 disabled:cursor-not-allowed",
        VARIANT_STYLES[variant],
        className
      )}
    >
      {pending ? pendingLabel : children}
    </button>
  );
}

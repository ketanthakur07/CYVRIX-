import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/cn";

type AlertTone = "info" | "success" | "warning" | "danger";

const ALERT_STYLES: Record<AlertTone, string> = {
  info: "bg-blue-50 border-blue-200 text-blue-900",
  success: "bg-green-50 border-green-200 text-green-900",
  warning: "bg-amber-50 border-amber-200 text-amber-900",
  danger: "bg-red-50 border-red-200 text-red-900",
};

const ALERT_ICONS: Record<AlertTone, React.ComponentType<{ className?: string }>> = {
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  danger: ShieldAlert,
};

/**
 * Alert. `children` is rendered as React text/nodes — never injected as
 * HTML. Server or repository text placed here stays inert.
 */
export function Alert({
  tone = "info",
  title,
  children,
  className,
  role,
}: {
  tone?: AlertTone;
  title?: string;
  children?: React.ReactNode;
  className?: string;
  role?: "status" | "alert";
}) {
  const Icon = ALERT_ICONS[tone];
  return (
    <div
      role={role ?? (tone === "danger" ? "alert" : "status")}
      className={cn("border rounded-lg p-3 text-sm", ALERT_STYLES[tone], className)}
    >
      <div className="flex items-start gap-2">
        <Icon className="h-4 w-4 mt-0.5 shrink-0" />
        <div className="min-w-0">
          {title && <p className="font-medium">{title}</p>}
          {children && <div className={cn("break-words", title && "mt-1 opacity-90")}>{children}</div>}
        </div>
      </div>
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: React.ReactNode;
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="border border-dashed border-gray-300 rounded-lg p-8 text-center">
      {icon && <div className="flex justify-center mb-2 text-gray-300">{icon}</div>}
      <p className="font-medium text-gray-700">{title}</p>
      {description && (
        <p className="text-sm text-gray-500 mt-1 break-words">{description}</p>
      )}
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  );
}

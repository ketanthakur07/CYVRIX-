import { AlertTriangle } from "lucide-react";
import { cn } from "@/lib/cn";
import { ApiError } from "@/lib/api";

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse bg-gray-200 rounded", className)} />;
}

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="animate-pulse space-y-4" role="status" aria-label={label}>
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-48 w-full rounded-lg" />
    </div>
  );
}

/**
 * Safe error presentation. Shows the classified message and, when the
 * server supplied one, the machine-readable reason code. Never renders
 * raw server text as HTML; never shows stack traces.
 */
export function ErrorState({
  title = "Something went wrong",
  error,
  onRetry,
}: {
  title?: string;
  error: unknown;
  onRetry?: () => void;
}) {
  const status = error instanceof ApiError ? error.status : undefined;
  const reason = error instanceof ApiError ? error.reasonCode : undefined;
  const message =
    error instanceof Error ? error.message : "The request could not be completed.";

  return (
    <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center max-w-2xl mx-auto">
      <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
      <p className="text-red-800 font-medium">{title}</p>
      <p className="text-red-700 text-sm mt-1 break-words">{message}</p>
      {(reason || status !== undefined) && (
        <p className="text-red-500 text-xs mt-2 font-mono">
          {reason ? `reason: ${reason}` : ""}
          {reason && status !== undefined ? " · " : ""}
          {status !== undefined ? `HTTP ${status}` : ""}
        </p>
      )}
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-4 text-sm font-medium text-red-700 underline hover:text-red-900"
        >
          Try again
        </button>
      )}
    </div>
  );
}

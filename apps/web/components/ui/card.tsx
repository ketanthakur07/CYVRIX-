import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { cn } from "@/lib/cn";

export function Card({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("bg-white border border-gray-200 rounded-lg", className)}>
      {children}
    </div>
  );
}

export function Section({
  title,
  icon,
  actions,
  children,
  className,
}: {
  title: string;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("bg-white border border-gray-200 rounded-lg p-4", className)}>
      <div className="flex items-center justify-between gap-3 mb-3">
        <h3 className="flex items-center gap-2 font-semibold text-gray-900 text-sm">
          {icon}
          {title}
        </h3>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function PageHeader({
  title,
  subtitle,
  backHref,
  backLabel,
  actions,
}: {
  title: string;
  subtitle?: React.ReactNode;
  backHref?: string;
  backLabel?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6">
      {backHref && (
        <Link
          href={backHref}
          className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 mb-3"
        >
          <ArrowLeft className="h-4 w-4" />
          {backLabel ?? "Back"}
        </Link>
      )}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold text-gray-900 break-words">{title}</h1>
          {subtitle && (
            <div className="text-sm text-gray-500 mt-1 break-words">{subtitle}</div>
          )}
        </div>
        {actions && <div className="shrink-0 flex items-center gap-2">{actions}</div>}
      </div>
    </div>
  );
}

/** Label/value grid for bounded metadata. Values render as inert text. */
export function DataList({
  children,
  columns = 2,
  className,
}: {
  children: React.ReactNode;
  columns?: 1 | 2 | 3 | 4;
  className?: string;
}) {
  const colClass =
    columns === 1
      ? "grid-cols-1"
      : columns === 2
      ? "grid-cols-1 sm:grid-cols-2"
      : columns === 3
      ? "grid-cols-1 sm:grid-cols-3"
      : "grid-cols-1 sm:grid-cols-2 lg:grid-cols-4";
  return (
    <dl className={cn("grid gap-x-6 gap-y-3 text-sm", colClass, className)}>
      {children}
    </dl>
  );
}

export function DataRow({
  label,
  children,
  mono,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-gray-500 text-xs">{label}</dt>
      <dd className={cn("text-gray-900 break-words", mono && "font-mono text-xs break-all")}>
        {children}
      </dd>
    </div>
  );
}

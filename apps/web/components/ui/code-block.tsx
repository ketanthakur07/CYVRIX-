import { cn } from "@/lib/cn";

/**
 * Renders untrusted text as inert monospace content. React escapes by
 * default; this component intentionally enables no raw-HTML injection.
 */
export function CodeBlock({
  children,
  className,
  dark,
}: {
  children: React.ReactNode;
  className?: string;
  dark?: boolean;
}) {
  return (
    <pre
      className={cn(
        "text-xs rounded p-3 overflow-x-auto whitespace-pre-wrap break-all border",
        dark
          ? "bg-gray-900 text-gray-100 border-gray-800"
          : "bg-gray-50 text-gray-800 border-gray-200",
        className
      )}
    >
      {children}
    </pre>
  );
}

/**
 * JSON viewer for untrusted structured payloads (audit payloads, run
 * results, evidence). Values are stringified and rendered as text.
 */
export function JsonBlock({ value }: { value: unknown }) {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2) ?? "(none)";
  } catch {
    text = "[unserializable value]";
  }
  return <CodeBlock>{text}</CodeBlock>;
}

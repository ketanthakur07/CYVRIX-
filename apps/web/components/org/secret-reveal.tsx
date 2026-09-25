"use client";

/**
 * V4.0 one-time secret reveal.
 *
 * The server returns an invitation token or API key secret exactly once.
 * This component is the only place either is rendered, and it:
 *   - never writes the value to storage, a URL, or a log,
 *   - offers an explicit copy action instead of auto-selecting,
 *   - states plainly that the value cannot be shown again.
 *
 * The value is rendered as React text, so it can never be interpreted as
 * HTML even if a server response were crafted to contain markup.
 */
import { useState } from "react";
import { Check, Copy, KeyRound } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

export function SecretReveal({
  label,
  secret,
  title,
  hint,
}: {
  label: string;
  secret: string;
  title: string;
  hint?: string;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      // Clipboard can be unavailable (permissions/insecure context). The
      // value stays visible so the user can copy it manually.
    }
  };

  return (
    <Alert tone="warning" title={title} className="mb-4">
      <p className="mb-2">
        {hint ??
          "This value is shown once and cannot be retrieved again. Store it now."}
      </p>
      <div className="flex items-center gap-2">
        <label className="sr-only" htmlFor={`secret-${label}`}>
          {label}
        </label>
        <code
          id={`secret-${label}`}
          className="flex-1 min-w-0 block rounded border border-amber-300 bg-white px-2 py-1.5 font-mono text-xs text-gray-800 break-all"
        >
          {secret}
        </code>
        <Button variant="secondary" onClick={copy} type="button">
          {copied ? (
            <>
              <Check className="h-4 w-4" />
              Copied
            </>
          ) : (
            <>
              <Copy className="h-4 w-4" />
              Copy
            </>
          )}
        </Button>
      </div>
      <p className="mt-2 text-xs inline-flex items-center gap-1 opacity-80">
        <KeyRound className="h-3 w-3" />
        Only a hash of this value is stored on the server.
      </p>
    </Alert>
  );
}

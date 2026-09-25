"use client";

import { useEffect, useRef, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "./button";

/**
 * Accessible confirmation dialog for security-critical actions.
 *
 * Rules (Phase 25 / 44):
 * - Describes exactly what will happen and what will NOT happen.
 * - Never a generic "Are you sure?" for dangerous operations.
 * - Keyboard-safe: Escape closes, focus starts inside, Tab stays inside.
 * - Optional type-to-confirm phrase for irreversible transitions.
 * - Confirmation here is a UX guard ONLY; the server remains the authority.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  consequences,
  confirmLabel = "Confirm",
  confirmPhrase,
  danger,
  pending,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  description: string;
  consequences?: string[];
  confirmLabel?: string;
  confirmPhrase?: string;
  danger?: boolean;
  pending?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [typed, setTyped] = useState("");
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      setTyped("");
      return;
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !pending) {
        onCancel();
      }
      if (e.key === "Tab" && panelRef.current) {
        const focusable = panelRef.current.querySelectorAll<HTMLElement>(
          'button, input, [href], [tabindex]:not([tabindex="-1"])'
        );
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    // Move focus into the dialog when it opens.
    const timer = window.setTimeout(() => {
      panelRef.current
        ?.querySelector<HTMLElement>('input, button')
        ?.focus();
    }, 0);
    return () => {
      document.removeEventListener("keydown", onKey);
      window.clearTimeout(timer);
    };
  }, [open, pending, onCancel]);

  if (!open) return null;

  const phraseOk = !confirmPhrase || typed.trim() === confirmPhrase;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      role="presentation"
      onClick={() => {
        if (!pending) onCancel();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-desc"
        className="bg-white rounded-lg shadow-xl border border-gray-200 w-full max-w-lg p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <h2
          id="confirm-title"
          className="text-lg font-semibold flex items-center gap-2 text-gray-900"
        >
          {danger && <AlertTriangle className="h-5 w-5 text-red-600" />}
          {title}
        </h2>
        <p id="confirm-desc" className="text-sm text-gray-600 mt-2 break-words">
          {description}
        </p>

        {consequences && consequences.length > 0 && (
          <ul className="mt-3 text-sm text-gray-700 list-disc list-inside space-y-1">
            {consequences.map((c, i) => (
              <li key={i} className="break-words">
                {c}
              </li>
            ))}
          </ul>
        )}

        {confirmPhrase && (
          <div className="mt-4">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Type <span className="font-mono">{confirmPhrase}</span> to confirm
            </label>
            <input
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              className="w-full border border-gray-300 rounded p-2 text-sm font-mono"
              autoComplete="off"
            />
          </div>
        )}

        <div className="flex justify-end gap-3 mt-5">
          <Button variant="secondary" onClick={onCancel} disabled={pending}>
            Cancel
          </Button>
          <Button
            variant={danger ? "danger" : "primary"}
            onClick={onConfirm}
            disabled={!phraseOk}
            pending={pending}
            pendingLabel="Working…"
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

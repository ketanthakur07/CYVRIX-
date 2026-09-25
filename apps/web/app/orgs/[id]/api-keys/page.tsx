"use client";

/**
 * V4.0 API keys.
 *
 * A key authenticates the /api/v1 public surface and is bound to ONE
 * organization — the organization is derived from the key, never from the
 * request, so a key can never reach another tenant. Scopes are narrower
 * than member capabilities: no scope can manage members, policy or the
 * organization itself.
 */
import { useState } from "react";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, ShieldAlert } from "lucide-react";
import { createApiKey, fetchApiKeys, revokeApiKey } from "@/lib/api";
import { useOrg, useOrgCapabilities } from "@/lib/org";
import { Alert, EmptyState } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, Section } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { OrgHeader } from "@/components/org/org-header";
import { SecretReveal } from "@/components/org/secret-reveal";
import {
  API_SCOPES,
  HIGH_IMPACT_API_SCOPES,
  ORG_CAP,
} from "@/lib/types";
import type { OrgApiKeyCreated } from "@/lib/types";
import { apiKeyTone, apiKeyStatus, formatTime } from "@/lib/workflow";

export default function OrganizationApiKeysPage() {
  const params = useParams<{ id: string }>();
  const organizationId = params?.id;
  const { organizations } = useOrg();
  const caps = useOrgCapabilities(organizationId);
  const queryClient = useQueryClient();

  const organization = organizations.find((o) => o.id === organizationId);
  const canManage = caps.hasCapability(ORG_CAP.MANAGE_API_KEYS);

  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["findings:read"]);
  const [expiresAt, setExpiresAt] = useState("");
  const [issued, setIssued] = useState<OrgApiKeyCreated | null>(null);

  const keysQuery = useQuery({
    queryKey: ["org-api-keys", organizationId],
    queryFn: () => fetchApiKeys(organizationId as string),
    enabled: !!organizationId && !!organization && canManage,
  });

  const invalidateKeys = () => {
    void queryClient.invalidateQueries({ queryKey: ["org-api-keys", organizationId] });
  };

  const createMutation = useMutation({
    mutationFn: () =>
      createApiKey(organizationId as string, {
        name: name.trim(),
        scopes,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      }),
    onSuccess: (key) => {
      setIssued(key);
      setName("");
      setExpiresAt("");
      setScopes(["findings:read"]);
      invalidateKeys();
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (keyId: string) =>
      revokeApiKey(organizationId as string, keyId),
    onSuccess: invalidateKeys,
  });

  if (!organization) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <Card className="p-8 text-center">
          <p className="font-medium text-gray-700">Organization not found</p>
          <p className="text-sm text-gray-500 mt-1">
            It either does not exist or your membership is not active.
          </p>
        </Card>
      </div>
    );
  }

  const toggleScope = (scope: string) => {
    setScopes((prev) =>
      prev.includes(scope)
        ? prev.filter((s) => s !== scope)
        : [...prev, scope]
    );
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <OrgHeader organization={organization} />

      {issued && (
        <SecretReveal
          label="api-key-secret"
          secret={issued.secret}
          title="API key created"
          hint="Copy this key now. The server stores only its hash, so it cannot be shown again."
        />
      )}

      {!canManage ? (
        <Alert tone="warning" title="Not available">
          Your role does not include MANAGE_API_KEYS.
        </Alert>
      ) : (
        <>
          <Section
            title="Create API key"
            icon={<Plus className="h-4 w-4" />}
          >
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (name.trim().length === 0 || scopes.length === 0) return;
                createMutation.mutate();
              }}
            >
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
                <div>
                  <label
                    htmlFor="key-name"
                    className="block text-xs text-gray-500 mb-1"
                  >
                    Name
                  </label>
                  <input
                    id="key-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    maxLength={120}
                    placeholder="CI pipeline"
                    className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label
                    htmlFor="key-expires"
                    className="block text-xs text-gray-500 mb-1"
                  >
                    Expires (optional)
                  </label>
                  <input
                    id="key-expires"
                    type="date"
                    value={expiresAt}
                    onChange={(e) => setExpiresAt(e.target.value)}
                    className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
                  />
                </div>
              </div>

              <fieldset className="mb-4">
                <legend className="text-xs text-gray-500 mb-2">
                  Scopes ({scopes.length} selected)
                </legend>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {API_SCOPES.map((scope) => {
                    const highImpact = HIGH_IMPACT_API_SCOPES.includes(scope);
                    return (
                      <label
                        key={scope}
                        className="flex items-center gap-2 text-sm text-gray-800"
                      >
                        <input
                          type="checkbox"
                          checked={scopes.includes(scope)}
                          onChange={() => toggleScope(scope)}
                          className="rounded border-gray-300"
                        />
                        <code className="font-mono text-xs">{scope}</code>
                        {highImpact && (
                          <Badge tone="warning" title="High-impact scope">
                            high impact
                          </Badge>
                        )}
                      </label>
                    );
                  })}
                </div>
              </fieldset>

              {scopes.some((s) => HIGH_IMPACT_API_SCOPES.includes(s)) && (
                <Alert tone="warning" className="mb-4" title="High-impact scope selected">
                  This key will be able to propose actions or export audit
                  history for the whole organization. Issue it only where it
                  is genuinely needed.
                </Alert>
              )}

              <Button
                type="submit"
                pending={createMutation.isPending}
                pendingLabel="Creating…"
                disabled={name.trim().length === 0 || scopes.length === 0}
              >
                <KeyRound className="h-4 w-4" />
                Create key
              </Button>
            </form>

            {createMutation.isError && (
              <p className="text-sm text-red-700 mt-3" role="alert">
                {createMutation.error instanceof Error
                  ? createMutation.error.message
                  : "Could not create the key."}
              </p>
            )}
          </Section>

          <Section
            className="mt-5"
            title="Active keys"
            icon={<KeyRound className="h-4 w-4" />}
          >
            {keysQuery.isLoading ? (
              <LoadingBlock label="Loading API keys" />
            ) : keysQuery.isError ? (
              <ErrorState
                title="API keys unavailable"
                error={keysQuery.error}
                onRetry={() => keysQuery.refetch()}
              />
            ) : (keysQuery.data ?? []).length === 0 ? (
              <EmptyState
                icon={<KeyRound className="h-8 w-8" />}
                title="No API keys"
                description="Create one above to use the /api/v1 public API."
              />
            ) : (
              <ul className="divide-y">
                {(keysQuery.data ?? []).map((key) => {
                  const revoked = !!key.revoked_at;
                  return (
                    <li
                      key={key.id}
                      className="py-3 flex flex-wrap items-center justify-between gap-3"
                    >
                      <div className="min-w-0">
                        <p className="text-sm text-gray-900 flex items-center gap-2">
                          {key.name}
                          <Badge tone={apiKeyTone(key)}>{apiKeyStatus(key)}</Badge>
                        </p>
                        <p className="text-xs text-gray-500 font-mono">
                          {key.prefix}…
                        </p>
                        <p className="text-xs text-gray-500 mt-1">
                          scopes:{" "}
                          {key.scopes.length > 0
                            ? key.scopes.join(", ")
                            : "none"}
                        </p>
                        <p className="text-xs text-gray-400 mt-0.5">
                          last used {formatTime(key.last_used_at)}
                          {key.expires_at
                            ? ` · expires ${formatTime(key.expires_at)}`
                            : " · no expiry"}
                        </p>
                      </div>
                      {!revoked && (
                        <Button
                          variant="danger"
                          pending={revokeMutation.isPending}
                          disabled={revokeMutation.isPending}
                          onClick={() => revokeMutation.mutate(key.id)}
                        >
                          <ShieldAlert className="h-4 w-4" />
                          Revoke
                        </Button>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
            {revokeMutation.isError && (
              <p className="text-sm text-red-700 mt-3" role="alert">
                {revokeMutation.error instanceof Error
                  ? revokeMutation.error.message
                  : "Could not revoke the key."}
              </p>
            )}
          </Section>
        </>
      )}
    </div>
  );
}

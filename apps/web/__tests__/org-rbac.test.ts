/**
 * V4.0 RBAC + presentation semantics.
 *
 * The client never decides authority, but it does decide what it SHOWS.
 * These tests pin the fail-closed properties that keep the UI truthful:
 * a non-ACTIVE membership confers nothing, an unknown capability is
 * never granted, and an unrecognised state renders neutral rather than
 * looking approved.
 */
import {
  API_SCOPES,
  HIGH_IMPACT_API_SCOPES,
  MEMBERSHIP_STATES,
  ORG_CAP,
  ORG_ROLES,
  ORG_ROLE_DESCRIPTIONS,
  ORG_ROLE_LABELS,
  effectiveCapabilities,
  hasOrgCapability,
} from "@/lib/types";
import {
  MEMBERSHIP_TONE,
  ORG_ROLE_TONE,
  ORG_STATE_TONE,
  apiKeyStatus,
  apiKeyTone,
  invitationStatusLabel,
  invitationTone,
  toneFor,
} from "@/lib/workflow";

const ALL_CAPS = Object.values(ORG_CAP) as string[];

describe("effectiveCapabilities (fail closed)", () => {
  it("grants capabilities for an ACTIVE membership", () => {
    expect(effectiveCapabilities([ORG_CAP.MANAGE_MEMBERS], "ACTIVE")).toEqual([
      ORG_CAP.MANAGE_MEMBERS,
    ]);
  });

  it.each(["SUSPENDED", "INVITED", "REMOVED", "UNKNOWN", "", null, undefined])(
    "grants nothing for membership state %p",
    (state) => {
      expect(
        effectiveCapabilities([ORG_CAP.MANAGE_MEMBERS], state as string | null)
      ).toEqual([]);
    }
  );

  it("grants nothing when the capability payload is missing", () => {
    expect(effectiveCapabilities(undefined, "ACTIVE")).toEqual([]);
  });

  it("never invents capabilities that are not in the payload", () => {
    // The client must not derive capabilities from the role.
    expect(
      effectiveCapabilities([ORG_CAP.VIEW_ACTIONS], "ACTIVE")
    ).not.toContain(ORG_CAP.MANAGE_MEMBERS);
  });
});

describe("hasOrgCapability", () => {
  it("is true only for a capability the server sent, on an ACTIVE membership", () => {
    expect(
      hasOrgCapability([ORG_CAP.MANAGE_POLICY], "ACTIVE", ORG_CAP.MANAGE_POLICY)
    ).toBe(true);
  });

  it("is false for a capability the caller does not have", () => {
    expect(
      hasOrgCapability([ORG_CAP.VIEW_ACTIONS], "ACTIVE", ORG_CAP.DELETE_ORGANIZATION)
    ).toBe(false);
  });

  it("is false when the membership is not ACTIVE, even if the capability is cached", () => {
    for (const cap of ALL_CAPS) {
      expect(hasOrgCapability([cap], "SUSPENDED", cap)).toBe(false);
    }
  });

  it("is false for an empty or unknown capability name", () => {
    expect(hasOrgCapability([ORG_CAP.VIEW_ACTIONS], "ACTIVE", "")).toBe(false);
    expect(
      hasOrgCapability([ORG_CAP.VIEW_ACTIONS], "ACTIVE", "SUPERUSER")
    ).toBe(false);
  });
});

describe("role catalogue", () => {
  it("labels and describes every role", () => {
    for (const role of ORG_ROLES) {
      expect(ORG_ROLE_LABELS[role]).toBeTruthy();
      expect(ORG_ROLE_DESCRIPTIONS[role]).toBeTruthy();
    }
  });

  it("has no capability named as a wildcard or superuser", () => {
    for (const cap of ALL_CAPS) {
      expect(cap).not.toMatch(/\b(ALL|SUPERUSER|ADMIN_ALL|\*)\b/);
    }
  });

  it("membership states match the server enum order-independently", () => {
    expect([...MEMBERSHIP_STATES].sort()).toEqual(
      ["ACTIVE", "INVITED", "REMOVED", "SUSPENDED"].sort()
    );
  });
});

describe("API key scopes", () => {
  it("marks every high-impact scope as a real scope", () => {
    for (const scope of HIGH_IMPACT_API_SCOPES) {
      expect(API_SCOPES).toContain(scope);
    }
  });

  it("grants no scope that manages members, policy or the organization", () => {
    for (const scope of API_SCOPES) {
      expect(scope).not.toMatch(/members|policy|organi[sz]ation|transfer|delete/i);
    }
  });
});

describe("presentation tones never overstate", () => {
  it("renders an unknown state as neutral", () => {
    expect(toneFor(MEMBERSHIP_TONE, "WHATEVER")).toBe("neutral");
    expect(toneFor(ORG_ROLE_TONE, "")).toBe("neutral");
    expect(toneFor(ORG_STATE_TONE, null)).toBe("neutral");
  });

  it("distinguishes active from inactive memberships", () => {
    expect(toneFor(MEMBERSHIP_TONE, "ACTIVE")).toBe("success");
    expect(toneFor(MEMBERSHIP_TONE, "SUSPENDED")).toBe("warning");
    expect(toneFor(MEMBERSHIP_TONE, "REMOVED")).toBe("neutral");
  });
});

describe("invitation lifecycle labels", () => {
  const past = new Date(Date.now() - 86_400_000).toISOString();
  const future = new Date(Date.now() + 86_400_000).toISOString();

  it("reports pending, accepted, revoked and expired", () => {
    expect(invitationStatusLabel({ expires_at: future })).toBe("pending");
    expect(invitationStatusLabel({ accepted_at: future })).toBe("accepted");
    expect(invitationStatusLabel({ revoked_at: future })).toBe("revoked");
    expect(invitationStatusLabel({ expires_at: past })).toBe("expired");
  });

  it("prefers terminal outcomes over expiry", () => {
    expect(invitationStatusLabel({ revoked_at: future, expires_at: past })).toBe(
      "revoked"
    );
    expect(invitationTone({ revoked_at: future })).toBe("danger");
    expect(invitationTone({ accepted_at: future })).toBe("success");
  });
});

describe("API key lifecycle", () => {
  const past = new Date(Date.now() - 86_400_000).toISOString();
  const future = new Date(Date.now() + 86_400_000).toISOString();

  it("reports active, revoked and expired", () => {
    expect(apiKeyStatus({ expires_at: future })).toBe("active");
    expect(apiKeyStatus({})).toBe("active");
    expect(apiKeyStatus({ revoked_at: future })).toBe("revoked");
    expect(apiKeyStatus({ expires_at: past })).toBe("expired");
  });

  it("shows a revoked key as danger, never as success", () => {
    expect(apiKeyTone({ revoked_at: future })).toBe("danger");
    expect(apiKeyTone({ expires_at: past })).toBe("neutral");
  });
});

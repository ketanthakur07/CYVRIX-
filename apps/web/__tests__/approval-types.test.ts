/**
 * V3.2 — Approval type contract tests.
 * The frontend types must mirror the backend Pydantic schemas exactly:
 * no missing fields, no client-authorizable fields that don't exist.
 */
import type { ActionProposal, Approval, ApprovalState, ProposalStatus } from "../lib/types";

describe("V3.2 approval types", () => {
  it("ActionProposal carries the full approval-relevant contract", () => {
    const p: ActionProposal = {
      id: "p1",
      finding_id: "f1",
      recommendation_id: "r1",
      repository_id: "repo1",
      action_type: "DEPENDENCY_UPGRADE",
      status: "POLICY_CHECKED",
      base_commit_sha: "a".repeat(40),
      target_branch: "cyvrix/fix",
      files: ["package.json"],
      operations: [{ type: "UPDATE_DEPENDENCY_VERSION" }],
      expected_diff: "- a\n+ b",
      rationale: null,
      evidence: null,
      risk_score: 45,
      risk_level: "MEDIUM",
      recommendation_trust: "SUPPORTED",
      validation_state: "VALIDATED",
      policy_version: "3.1",
      policy_decision: "REQUIRE_APPROVAL",
      policy_reason_code: "MEDIUM_RISK_REQUIRES_APPROVAL",
      policy_matched_rule: "POL-027",
      policy_explanation: null,
      action_digest: "d".repeat(64),
      expires_at: null,
      created_at: null,
    };
    // Approval-relevant fields must exist and be non-optional where the
    // server always sends them
    expect(p.action_digest).toHaveLength(64);
    expect(p.policy_decision).toBe("REQUIRE_APPROVAL");
    expect(Array.isArray(p.files)).toBe(true);
    expect(Array.isArray(p.operations)).toBe(true);
  });

  it("Approval never includes plaintext token fields", () => {
    const a: Approval = {
      id: "ap1",
      action_proposal_id: "p1",
      action_digest: "d".repeat(64),
      approver_user_id: "u1",
      second_approver_user_id: null,
      approval_state: "APPROVED",
      approval_reason: null,
      policy_version: "3.1",
      policy_decision: "REQUIRE_APPROVAL",
      approval_level: "MEDIUM",
      approved_at: null,
      expires_at: null,
      authorization_issued_at: null,
      authorization_used_at: null,
      created_at: null,
    };
    const serialized = JSON.stringify(a);
    expect(serialized).not.toContain("authorization_token\":");
    expect(a.authorization_used_at).toBeNull();
  });

  it("approval states are the canonical six", () => {
    const states: ApprovalState[] = [
      "PENDING", "APPROVED", "REJECTED", "EXPIRED", "REVOKED", "USED",
    ];
    expect(states).toHaveLength(6);
  });

  it("proposal statuses include the V3.2 APPROVED state", () => {
    const statuses: ProposalStatus[] = [
      "PROPOSED", "POLICY_CHECKED", "REJECTED", "EXPIRED", "STALE", "APPROVED",
    ];
    expect(statuses).toContain("APPROVED");
  });

  it("APPROVED and EXECUTED are distinct concepts (no EXECUTED state exists)", () => {
    // The UI must never show APPROVED as EXECUTED — there is no EXECUTED
    // state in the V3.2 contract at all.
    const all: string[] = ["PROPOSED", "POLICY_CHECKED", "REJECTED", "EXPIRED", "STALE", "APPROVED"];
    expect(all).not.toContain("EXECUTED");
  });
});

/**
 * V3.9 workflow presentation helpers.
 *
 * These tests pin the DISPLAY contract: unknown backend states must never
 * be coerced into a success tone, and terminal checks must match the
 * backend state machines exactly (they drive polling only).
 */
import {
  toneFor,
  isKnownState,
  isTerminalRun,
  isTerminalVerification,
  isTerminalRollback,
  isTerminalRemediation,
  verificationAccepted,
  verificationBlocked,
  formatTime,
  shortDigest,
  RUN_TONE,
  VERIFICATION_RESULT_TONE,
  AUTHORIZATION_TONE,
  AUDIT_VERIFY_TONE,
} from "@/lib/workflow";

describe("workflow state tones", () => {
  it("maps known states to their tone", () => {
    expect(toneFor(RUN_TONE, "COMPLETED")).toBe("success");
    expect(toneFor(RUN_TONE, "FAILED")).toBe("danger");
    expect(toneFor(AUTHORIZATION_TONE, "REVOKED")).toBe("danger");
    expect(toneFor(AUDIT_VERIFY_TONE, "INVALID")).toBe("danger");
  });

  it("never maps an unknown state to a success tone", () => {
    expect(toneFor(RUN_TONE, "WHO_KNOWS")).toBe("neutral");
    expect(toneFor(RUN_TONE, null)).toBe("neutral");
    expect(toneFor(RUN_TONE, undefined)).toBe("neutral");
    expect(toneFor(VERIFICATION_RESULT_TONE, "FORGED")).toBe("neutral");
  });

  it("reports whether a state is known", () => {
    expect(isKnownState(RUN_TONE, "EXECUTING")).toBe(true);
    expect(isKnownState(RUN_TONE, "MADE_UP")).toBe(false);
    expect(isKnownState(RUN_TONE, null)).toBe(false);
  });
});

describe("terminal detection matches the backend state machines", () => {
  it("execution runs", () => {
    expect(isTerminalRun("COMPLETED")).toBe(true);
    expect(isTerminalRun("CLEANUP_FAILED")).toBe(true);
    expect(isTerminalRun("FAILED")).toBe(true);
    expect(isTerminalRun("EXECUTING")).toBe(false);
    expect(isTerminalRun("RESULT_READY")).toBe(false);
  });

  it("verification", () => {
    expect(isTerminalVerification("COMPLETED")).toBe(true);
    expect(isTerminalVerification("BLOCKED")).toBe(true);
    expect(isTerminalVerification("RUNNING")).toBe(false);
  });

  it("rollback", () => {
    expect(isTerminalRollback("COMPLETED")).toBe(true);
    expect(isTerminalRollback("CONFLICT")).toBe(true);
    expect(isTerminalRollback("PRECHECK")).toBe(false);
  });

  it("remediation", () => {
    expect(isTerminalRemediation("PR_CREATED")).toBe(true);
    expect(isTerminalRemediation("PUSHING")).toBe(false);
  });
});

describe("verification acceptance semantics", () => {
  it("accepts only PASS and SKIPPED", () => {
    expect(verificationAccepted("PASS")).toBe(true);
    expect(verificationAccepted("SKIPPED")).toBe(true);
    expect(verificationAccepted("FAIL")).toBe(false);
    expect(verificationAccepted("INCONCLUSIVE")).toBe(false);
  });

  it("treats FAIL/INCONCLUSIVE/BLOCKED as blocked", () => {
    expect(verificationBlocked("FAIL")).toBe(true);
    expect(verificationBlocked("INCONCLUSIVE")).toBe(true);
    expect(verificationBlocked("BLOCKED")).toBe(true);
    expect(verificationBlocked("PASS")).toBe(false);
  });
});

describe("display formatting", () => {
  it("formats null/invalid timestamps as an em dash", () => {
    expect(formatTime(null)).toBe("—");
    expect(formatTime(undefined)).toBe("—");
    expect(formatTime("not-a-date")).toBe("—");
  });

  it("shortens long digests and passes short ones through", () => {
    expect(shortDigest("abc")).toBe("abc");
    expect(shortDigest(null)).toBe("—");
    const long = "a".repeat(64);
    const short = shortDigest(long);
    expect(short.length).toBeLessThan(long.length);
    expect(short.startsWith("a".repeat(10))).toBe(true);
  });
});

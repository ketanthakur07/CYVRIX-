/**
 * Type constants and utility function tests.
 * Verifies display constants and helper functions are correct.
 */
import {
  SEVERITY_COLORS,
  RISK_LEVEL_COLORS,
  VERDICT_COLORS,
  STATUS_COLORS,
  SCAN_STATUS_STEPS,
  isTerminalStatus,
} from "@/lib/types";

describe("Display constants", () => {
  it("has color entries for all severity levels", () => {
    expect(SEVERITY_COLORS.CRITICAL).toBeDefined();
    expect(SEVERITY_COLORS.HIGH).toBeDefined();
    expect(SEVERITY_COLORS.MEDIUM).toBeDefined();
    expect(SEVERITY_COLORS.LOW).toBeDefined();
    expect(SEVERITY_COLORS.UNKNOWN).toBeDefined();
  });

  it("has color entries for all risk levels", () => {
    expect(RISK_LEVEL_COLORS.CRITICAL).toBeDefined();
    expect(RISK_LEVEL_COLORS.HIGH).toBeDefined();
    expect(RISK_LEVEL_COLORS.MEDIUM).toBeDefined();
    expect(RISK_LEVEL_COLORS.LOW).toBeDefined();
    expect(RISK_LEVEL_COLORS.INFO).toBeDefined();
  });

  it("has color entries for all verdicts", () => {
    expect(VERDICT_COLORS.CONFIRMED).toBeDefined();
    expect(VERDICT_COLORS.LIKELY).toBeDefined();
    expect(VERDICT_COLORS.UNLIKELY).toBeDefined();
    expect(VERDICT_COLORS.FALSE_POSITIVE).toBeDefined();
    expect(VERDICT_COLORS.UNKNOWN).toBeDefined();
  });

  it("has status colors for all scan statuses", () => {
    expect(STATUS_COLORS.COMPLETED).toBeDefined();
    expect(STATUS_COLORS.FAILED).toBeDefined();
    expect(STATUS_COLORS.QUEUED).toBeDefined();
    expect(STATUS_COLORS.CLONING).toBeDefined();
    expect(STATUS_COLORS.SCANNING).toBeDefined();
    expect(STATUS_COLORS.ANALYZING).toBeDefined();
  });

  it("defines scan status steps in correct order", () => {
    expect(SCAN_STATUS_STEPS).toEqual([
      "QUEUED",
      "CLONING",
      "SCANNING",
      "ANALYZING",
      "COMPLETED",
    ]);
  });
});

describe("isTerminalStatus", () => {
  it("returns true for COMPLETED", () => {
    expect(isTerminalStatus("COMPLETED")).toBe(true);
  });

  it("returns true for FAILED", () => {
    expect(isTerminalStatus("FAILED")).toBe(true);
  });

  it("returns false for QUEUED", () => {
    expect(isTerminalStatus("QUEUED")).toBe(false);
  });

  it("returns false for CLONING", () => {
    expect(isTerminalStatus("CLONING")).toBe(false);
  });

  it("returns false for SCANNING", () => {
    expect(isTerminalStatus("SCANNING")).toBe(false);
  });

  it("returns false for ANALYZING", () => {
    expect(isTerminalStatus("ANALYZING")).toBe(false);
  });
});

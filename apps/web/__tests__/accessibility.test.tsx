/**
 * V3.9 accessibility + interaction-safety tests (Phase 44 / 50 / 51).
 *
 * These are DOM-level assertions, not a substitute for a screen-reader
 * pass, but they pin the properties a security console must not lose:
 * dialogs are labelled and keyboard-dismissable, form controls are
 * labelled, and pending controls cannot be double-submitted.
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/alert";

describe("ConfirmDialog accessibility", () => {
  it("is a labelled modal dialog", () => {
    render(
      <ConfirmDialog
        open
        danger
        title="Emergency stop"
        description="Blocks all remediation mutations."
        consequences={["Admissions stop", "In-flight work is not killed"]}
        confirmLabel="Confirm"
        onConfirm={() => {}}
        onCancel={() => {}}
      />
    );
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    const labelledBy = dialog.getAttribute("aria-labelledby");
    expect(labelledBy).toBeTruthy();
    expect(document.getElementById(labelledBy as string)?.textContent).toContain(
      "Emergency stop"
    );
    expect(screen.getByText("Admissions stop")).toBeTruthy();
  });

  it("closes on Escape (keyboard dismissal)", () => {
    const onCancel = jest.fn();
    render(
      <ConfirmDialog
        open
        title="Pause"
        description="Pause the platform."
        onConfirm={() => {}}
        onCancel={onCancel}
      />
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("requires the confirmation phrase before enabling the action", () => {
    render(
      <ConfirmDialog
        open
        danger
        title="Emergency stop"
        description="Blocks all mutations."
        confirmPhrase="EMERGENCY_STOP"
        confirmLabel="Confirm"
        onConfirm={() => {}}
        onCancel={() => {}}
      />
    );
    const confirm = screen.getByRole("button", { name: "Confirm" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "EMERGENCY_STOP" },
    });
    expect(confirm.disabled).toBe(false);
  });

  it("does not render when closed", () => {
    render(
      <ConfirmDialog
        open={false}
        title="x"
        description="y"
        onConfirm={() => {}}
        onCancel={() => {}}
      />
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("Button interaction safety", () => {
  it("is disabled and reports busy while pending (blocks double submit)", () => {
    const onClick = jest.fn();
    render(
      <Button pending onClick={onClick}>
        Approve
      </Button>
    );
    const button = screen.getByRole("button") as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("aria-busy")).toBe("true");
    fireEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("exposes a stable accessible name", () => {
    render(<Button>Authorize this exact action</Button>);
    expect(
      screen.getByRole("button", { name: "Authorize this exact action" })
    ).toBeTruthy();
  });
});

describe("Alert roles", () => {
  it("danger alerts announce as alerts, others as status", () => {
    const { rerender } = render(<Alert tone="danger" title="Blocked" />);
    expect(screen.getByRole("alert")).toBeTruthy();
    rerender(<Alert tone="info" title="Read-only" />);
    expect(screen.getByRole("status")).toBeTruthy();
  });
});

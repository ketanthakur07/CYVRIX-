/**
 * V3.9 XSS tests for the shared workflow UI primitives.
 *
 * Untrusted data (repository names, branch names, commit messages, AI
 * output, audit payloads, error text) flows into these components. Every
 * one must render hostile content as inert text — no elements, no event
 * handlers, no script execution.
 */
import React from "react";
import { render, screen } from "@testing-library/react";
import { Alert, EmptyState } from "@/components/ui/alert";
import { Badge, StateBadge } from "@/components/ui/badge";
import { CodeBlock, JsonBlock } from "@/components/ui/code-block";
import { DataList, DataRow } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

const PAYLOADS = [
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  "javascript:alert(1)",
  '<iframe src="javascript:alert(1)">',
  '<body onload=alert(1)>',
  '<style>body{background:url(javascript:alert(1))}</style>',
  '"><a href="data:text/html,<script>alert(1)</script>">x</a>',
];

/**
 * Assert the container has no dangerous elements created from untrusted
 * content. `allowSvg` covers components that legitimately render a lucide
 * ICON (an <svg> whose path is static, never derived from input).
 */
function assertInert(container: HTMLElement, opts: { allowSvg?: boolean } = {}) {
  expect(container.querySelectorAll("script").length).toBe(0);
  expect(container.querySelectorAll("img").length).toBe(0);
  if (!opts.allowSvg) {
    expect(container.querySelectorAll("svg").length).toBe(0);
  }
  expect(container.querySelectorAll("iframe").length).toBe(0);
  expect(container.querySelectorAll("style").length).toBe(0);
  expect(container.querySelectorAll("a").length).toBe(0);
}

describe("V3.9 components render hostile content as inert text", () => {
  PAYLOADS.forEach((payload) => {
    it(`Badge: ${payload.slice(0, 32)}`, () => {
      const { container } = render(<Badge>{payload}</Badge>);
      expect(container.textContent).toContain(payload);
      assertInert(container);
    });

    it(`Alert: ${payload.slice(0, 32)}`, () => {
      const { container } = render(
        <Alert tone="danger" title={payload}>
          {payload}
        </Alert>
      );
      expect(container.textContent).toContain(payload);
      assertInert(container, { allowSvg: true });
    });

    it(`CodeBlock: ${payload.slice(0, 32)}`, () => {
      const { container } = render(<CodeBlock>{payload}</CodeBlock>);
      expect(container.querySelector("pre")?.textContent).toContain(payload);
      assertInert(container);
    });

    it(`DataRow: ${payload.slice(0, 32)}`, () => {
      const { container } = render(
        <DataList columns={1}>
          <DataRow label="branch">{payload}</DataRow>
        </DataList>
      );
      expect(container.textContent).toContain(payload);
      assertInert(container);
    });
  });

  it("JsonBlock escapes hostile payload values", () => {
    const { container } = render(
      <JsonBlock value={{ branch: '<img src=x onerror=alert(1)>', note: "<script>x</script>" }} />
    );
    expect(container.textContent).toContain("onerror=alert(1)");
    assertInert(container);
  });

  it("StateBadge renders an unknown backend state verbatim without crashing", () => {
    render(<StateBadge state="<script>alert(1)</script>" tone="neutral" />);
    expect(screen.getByText("<script>alert(1)</script>")).toBeTruthy();
  });

  it("EmptyState renders a hostile description as inert text", () => {
    const { container } = render(
      <EmptyState title="None" description={'<img src=x onerror=alert(1)>'} />
    );
    assertInert(container, { allowSvg: true });
  });

  it("Button label with hostile text stays inert", () => {
    const { container } = render(<Button>{'<img src=x onerror=alert(1)>'}</Button>);
    assertInert(container, { allowSvg: true });
    expect(container.querySelector("button")).toBeTruthy();
  });
});

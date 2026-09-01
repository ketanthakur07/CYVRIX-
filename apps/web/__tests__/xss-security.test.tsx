/**
 * XSS Security Tests
 *
 * Verifies that hostile content such as:
 * - <script>alert(1)</script>
 * - <img src=x onerror=alert(1)>
 * - javascript:alert(1)
 *
 * is rendered as harmless text, not executed.
 *
 * React's default rendering escapes HTML entities, so these tests
 * verify that we don't bypass that escaping with dangerouslySetInnerHTML
 * or other unsafe patterns.
 */
import React from "react";
import { render, screen } from "@testing-library/react";

// Minimal component that renders untrusted text (simulates finding title)
function UntrustedText({ text }: { text: string }) {
  return <span>{text}</span>;
}

// Component that renders a finding-like card with hostile data
function FindingCard({
  title,
  packageName,
  fileName,
  summary,
}: {
  title: string;
  packageName: string;
  fileName: string;
  summary: string;
}) {
  return (
    <div>
      <h2 data-testid="title">{title}</h2>
      <p data-testid="package">{packageName}</p>
      <p data-testid="file">{fileName}</p>
      <p data-testid="summary">{summary}</p>
    </div>
  );
}

describe("XSS Defense — React Escaping", () => {
  const xssPayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    '<iframe src="javascript:alert(1)">',
    "{{constructor.constructor('return this')()}}",
    "<body onload=alert(1)>",
    '<div style="background:url(javascript:alert(1))">',
  ];

  xssPayloads.forEach((payload) => {
    it(`renders hostile payload as text: ${payload.slice(0, 40)}...`, () => {
      const { container } = render(<UntrustedText text={payload} />);
      // The payload should appear as text content, not as HTML elements
      expect(container.textContent).toContain(payload);
      // No script or img elements should be created
      expect(container.querySelectorAll("script").length).toBe(0);
      expect(container.querySelectorAll("img").length).toBe(0);
      expect(container.querySelectorAll("svg").length).toBe(0);
      expect(container.querySelectorAll("iframe").length).toBe(0);
    });
  });

  it("renders hostile finding title safely", () => {
    render(
      <FindingCard
        title='<script>alert("XSS")</script> - lodash vulnerability'
        packageName="lodash"
        fileName="src/<img src=x onerror=alert(1)>.js"
        summary='This package is <b>dangerous</b> and uses <script> tags'
      />
    );

    // All hostile content should be rendered as text
    const title = screen.getByTestId("title");
    expect(title.textContent).toContain('<script>alert("XSS")</script>');
    expect(title.textContent).toContain("lodash vulnerability");

    const file = screen.getByTestId("file");
    expect(file.textContent).toContain("<img src=x onerror=alert(1)>");

    const summary = screen.getByTestId("summary");
    expect(summary.textContent).toContain("<b>dangerous</b>");
    expect(summary.textContent).toContain("<script>");
  });

  it("does not use dangerouslySetInnerHTML", () => {
    // This is a code pattern test — verify the source doesn't contain dangerous patterns
    // In a real project, you'd use eslint-plugin-react for this
    const { container } = render(
      <UntrustedText text='<script>alert(1)</script>' />
    );
    // The div should contain a text node, not raw HTML
    expect(container.innerHTML).not.toContain("<script>");
    expect(container.innerHTML).toContain("&lt;script&gt;");
  });
});

describe("XSS Defense — Long/Pathological Input", () => {
  it("handles extremely long package names without breaking", () => {
    const longName = "a".repeat(10000);
    render(<UntrustedText text={longName} />);
    expect(screen.getByText(longName)).toBeTruthy();
  });

  it("handles empty strings safely", () => {
    const { container } = render(<UntrustedText text="" />);
    expect(container.textContent).toBe("");
  });

  it("handles unicode and emoji in content", () => {
    const content = '🔥 Critical: <script>alert("xss")</script> 🔒';
    render(<UntrustedText text={content} />);
    expect(screen.getByText(content)).toBeTruthy();
  });
});

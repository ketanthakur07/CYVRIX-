import { Shield, Scan, Brain, BarChart3, GitBranch, ArrowRight } from "lucide-react";
import Link from "next/link";

export default function Home() {
  return (
    <div className="min-h-[calc(100vh-4rem)]">
      {/* Hero */}
      <section className="container mx-auto px-4 pt-20 pb-16 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-blue-50 text-blue-700 rounded-full text-sm font-medium mb-6">
          <Shield className="h-4 w-4" />
          Security Intelligence
        </div>
        <h1 className="text-5xl font-bold text-gray-900 mb-4 tracking-tight">
          CYVRIX
        </h1>
        <p className="text-xl text-gray-600 mb-8 max-w-2xl mx-auto">
          Autonomous Security Intelligence Platform. Detect known
          vulnerabilities in your dependencies, investigate with AI context, and
          understand your real risk.
        </p>
        <div className="flex gap-3 justify-center">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors"
          >
            Open Dashboard
            <ArrowRight className="h-4 w-4" />
          </Link>
          <a
            href="/api/github/connect"
            className="inline-flex items-center gap-2 px-6 py-3 bg-gray-100 text-gray-700 rounded-lg font-medium hover:bg-gray-200 transition-colors"
          >
            <GitBranch className="h-4 w-4" />
            Connect GitHub
          </a>
        </div>
      </section>

      {/* Capabilities */}
      <section className="container mx-auto px-4 pb-20">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto">
          <div className="bg-white border rounded-lg p-6 text-center">
            <Scan className="h-8 w-8 text-blue-500 mx-auto mb-3" />
            <h2 className="font-semibold text-gray-900 mb-2">Detect</h2>
            <p className="text-sm text-gray-600">
              Scan npm and PyPI dependencies against OSV vulnerability database.
              Findings are fingerprinted and deduplicated.
            </p>
          </div>
          <div className="bg-white border rounded-lg p-6 text-center">
            <Brain className="h-8 w-8 text-purple-500 mx-auto mb-3" />
            <h2 className="font-semibold text-gray-900 mb-2">Investigate</h2>
            <p className="text-sm text-gray-600">
              AI-powered investigation analyzes whether a vulnerability is
              relevant and exploitable in your specific codebase.
            </p>
          </div>
          <div className="bg-white border rounded-lg p-6 text-center">
            <BarChart3 className="h-8 w-8 text-orange-500 mx-auto mb-3" />
            <h2 className="font-semibold text-gray-900 mb-2">Assess</h2>
            <p className="text-sm text-gray-600">
              Deterministic risk scoring combines severity, exposure, and
              exploitability into an explainable risk score.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

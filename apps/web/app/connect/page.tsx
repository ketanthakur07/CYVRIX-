"use client";

import { useSearchParams } from "next/navigation";
import { useRouter } from "next/navigation";
import { Suspense, useEffect } from "react";
import { AlertTriangle, Shield } from "lucide-react";
import Link from "next/link";

function ConnectContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const error = searchParams.get("error");

  useEffect(() => {
    if (!error) {
      router.replace("/repositories?connected=true");
    }
  }, [error, router]);

  if (!error) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center py-12">
          <div className="animate-spin h-8 w-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-gray-600">Connecting to GitHub...</p>
        </div>
      </div>
    );
  }

  const errorMessages: Record<string, { title: string; description: string }> = {
    github_unavailable: {
      title: "GitHub is temporarily unavailable",
      description: "Please try again in a few minutes.",
    },
    auth_failed: {
      title: "Authentication failed",
      description: "The GitHub App may have been removed. Please reinstall it.",
    },
    no_repositories: {
      title: "No repositories found",
      description: "Make sure the GitHub App has access to at least one repository.",
    },
    missing_installation_id: {
      title: "Invalid callback",
      description: "The installation callback was missing required parameters.",
    },
  };

  const errorInfo = errorMessages[error] || {
    title: "Connection error",
    description: "An unexpected connection error occurred.",
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-md mx-auto mt-12">
        <div className="bg-white border rounded-lg p-8 text-center">
          <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h1 className="text-xl font-bold text-gray-900 mb-2">{errorInfo.title}</h1>
          <p className="text-gray-600 mb-6">{errorInfo.description}</p>
          <div className="flex gap-3 justify-center">
            <a
              href="/api/github/connect"
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md font-medium hover:bg-blue-700 transition-colors"
            >
              <Shield className="h-4 w-4" />
              Try Again
            </a>
            <Link
              href="/repositories"
              className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-md font-medium hover:bg-gray-200 transition-colors"
            >
              Back to Repositories
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ConnectPage() {
  return (
    <Suspense
      fallback={
        <div className="container mx-auto px-4 py-8">
          <div className="text-center py-12">
            <div className="animate-spin h-8 w-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-4" />
            <p className="text-gray-600">Loading...</p>
          </div>
        </div>
      }
    >
      <ConnectContent />
    </Suspense>
  );
}

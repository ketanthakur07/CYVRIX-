"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  LayoutDashboard,
  GitBranch,
  LogIn,
  LogOut,
  User,
  Activity,
  Gauge,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import { fetchOpsCapabilities } from "@/lib/api";

const baseItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/repositories", label: "Repositories", icon: GitBranch },
];

const consoleItems = [
  { href: "/operations", label: "Operations", icon: Gauge, capability: "VIEW_OPERATIONS" },
  { href: "/audit", label: "Audit", icon: Activity, capability: "VIEW_AUDIT" },
];

export function Navigation() {
  const pathname = usePathname();
  const { isAuthenticated, user, isLoading, login, logout } = useAuth();

  // Capabilities shape the UI only. The server independently authorizes
  // every route; hiding a link is a UX convenience, never a security
  // boundary. Fetched only when authenticated to avoid a 401 redirect.
  const capabilitiesQuery = useQuery({
    queryKey: ["ops-capabilities"],
    queryFn: fetchOpsCapabilities,
    enabled: isAuthenticated,
    staleTime: 5 * 60 * 1000,
  });

  const visibleConsoleItems = isAuthenticated
    ? consoleItems.filter((item) =>
        capabilitiesQuery.data?.capabilities.includes(item.capability)
      )
    : [];

  const items = [...baseItems, ...visibleConsoleItems];

  return (
    <header className="border-b bg-white">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <Link href="/" className="flex items-center gap-2 font-bold text-xl">
            <Shield className="h-6 w-6 text-blue-600" />
            CYVRIX
          </Link>
          <nav className="flex items-center gap-1" aria-label="Main">
            {items.map((item) => {
              const Icon = item.icon;
              const isActive = pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={isActive ? "page" : undefined}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-blue-50 text-blue-700"
                      : "text-gray-600 hover:text-gray-900 hover:bg-gray-50"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>
        <div className="flex items-center gap-4">
          {isLoading ? (
            <div className="h-8 w-8 rounded-full bg-gray-200 animate-pulse" />
          ) : isAuthenticated && user ? (
            <div className="flex items-center gap-3">
              <span className="text-sm text-gray-600 flex items-center gap-1">
                <User className="h-4 w-4" />
                {user.github_login || user.email}
              </span>
              <button
                onClick={logout}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-sm font-medium text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-md transition-colors"
              >
                <LogOut className="h-4 w-4" />
                Logout
              </button>
            </div>
          ) : (
            <button
              onClick={login}
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
            >
              <LogIn className="h-4 w-4" />
              Login with GitHub
            </button>
          )}
        </div>
      </div>
    </header>
  );
}

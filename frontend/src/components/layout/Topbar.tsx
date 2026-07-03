"use client";

import { Bell } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

export function Topbar() {
    const { user } = useAuth();

    const initials = user
        ? `${user.firstName.charAt(0)}${user.lastName.charAt(0)}`.toUpperCase()
        : "?";

    return (
        <header className="sticky top-0 z-30 border-b border-[var(--hms-border)] bg-[var(--hms-surface)]/80 px-6 py-3 backdrop-blur">
            <div className="flex items-center justify-end gap-4">
                <button
                    type="button"
                    className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)]"
                    aria-label="Notifications"
                >
                    <Bell className="h-5 w-5" strokeWidth={1.8} />
                </button>

                <div
                    className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-sm font-bold text-white"
                    title={user ? `${user.firstName} ${user.lastName}` : undefined}
                >
                    {initials}
                </div>
            </div>
        </header>
    );
}

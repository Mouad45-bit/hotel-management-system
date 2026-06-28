import { Bell, Search, User } from "lucide-react";

export function Topbar() {
    return (
        <header className="sticky top-0 z-30 border-b border-[var(--hms-border)] bg-[var(--hms-surface)]/80 px-6 py-3 backdrop-blur">
            <div className="flex items-center gap-4">
                <div className="relative flex-1">
                    <Search
                        aria-hidden="true"
                        className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-[var(--hms-text-muted)]"
                        strokeWidth={1.8}
                    />
                    <input
                        type="search"
                        disabled
                        placeholder="Recherche globale à venir..."
                        className="w-full cursor-not-allowed rounded-2xl border border-[var(--hms-border)] bg-slate-50 py-2.5 pl-12 pr-4 text-sm text-[var(--hms-text-muted)] placeholder:text-[rgba(13,9,7,0.38)] focus:outline-none"
                    />
                </div>

                <button
                    type="button"
                    className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)]"
                    aria-label="Notifications"
                >
                    <Bell className="h-5 w-5" strokeWidth={1.8} />
                </button>

                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-white">
                    <User className="h-5 w-5" strokeWidth={1.8} />
                </div>
            </div>
        </header>
    );
}

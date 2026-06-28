import { Bell, User } from "lucide-react";

export function Topbar() {
    return (
        <header className="sticky top-0 z-30 border-b border-white/60 bg-white/55 px-6 py-4 shadow-[0_18px_55px_rgba(15,23,42,0.12)] backdrop-blur-2xl backdrop-saturate-150 supports-[backdrop-filter]:bg-white/45">
            <div className="flex min-h-14 items-center justify-end gap-4">
                <button
                    type="button"
                    className="flex h-11 w-11 shrink-0 cursor-pointer items-center justify-center rounded-xl border border-white/70 bg-white/45 text-[var(--hms-text-muted)] shadow-sm transition-colors hover:border-slate-200 hover:bg-white/75 hover:text-[var(--hms-text)]"
                    aria-label="Notifications"
                >
                    <Bell className="h-5 w-5" strokeWidth={1.8} />
                </button>

                <div className="flex h-11 w-11 shrink-0 cursor-pointer items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-white">
                    <User className="h-5 w-5" strokeWidth={1.8} />
                </div>
            </div>
        </header>
    );
}

import { Bell, Search, User } from "lucide-react";

export function Topbar() {
    return (
        <header className="sticky top-0 z-30 border-b border-zinc-200 bg-white/80 px-6 py-3 backdrop-blur">
            <div className="flex items-center gap-4">
                <div className="relative flex-1">
                    <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-zinc-400" />
                    <input
                        type="search"
                        disabled
                        placeholder="Recherche globale à venir..."
                        className="w-full cursor-not-allowed rounded-2xl border border-zinc-200 bg-zinc-50 py-2.5 pl-12 pr-4 text-sm text-zinc-500 placeholder:text-zinc-400 focus:outline-none"
                    />
                </div>

                <button
                    type="button"
                    className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-900"
                    aria-label="Notifications"
                >
                    <Bell className="h-5 w-5" />
                </button>

                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-zinc-900 text-white">
                    <User className="h-5 w-5" />
                </div>
            </div>
        </header>
    );
}

import { Bell, Search, UserRound } from "lucide-react";

interface TopbarProps {
    title: string;
    description?: string;
}

export function Topbar({ title, description }: TopbarProps) {
    return (
        <header className="flex h-24 items-center border-b border-[var(--hms-soft-border)] bg-white px-5 sm:px-8 lg:px-12">
            <div className="sr-only">
                <h1>{title}</h1>
                {description && <p>{description}</p>}
            </div>

            <div className="mx-auto flex w-full max-w-[1200px] items-center justify-between gap-4">
                <div className="relative hidden flex-1 md:block md:max-w-2xl">
                    <Search
                        aria-hidden="true"
                        className="pointer-events-none absolute left-5 top-1/2 h-5 w-5 -translate-y-1/2 text-[var(--hms-text-muted)]"
                        strokeWidth={1.8}
                    />

                    <input
                        type="search"
                        placeholder="Recherche globale à venir…"
                        disabled
                        className="h-12 w-full rounded-2xl border border-[var(--hms-border)] bg-white pl-13 pr-4 text-sm text-[var(--hms-text)] placeholder:text-[var(--hms-text-muted)] disabled:cursor-not-allowed disabled:opacity-100"
                        aria-label="Recherche globale à venir"
                    />
                </div>

                <div className="ml-auto flex items-center gap-3">
                    <button
                        type="button"
                        className="flex h-12 w-12 cursor-pointer items-center justify-center rounded-2xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                        aria-label="Notifications"
                    >
                        <Bell aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </button>

                    <button
                        type="button"
                        className="flex h-12 w-12 cursor-pointer items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-white transition-colors hover:bg-[var(--hms-primary-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                        aria-label="Profil utilisateur"
                    >
                        <UserRound aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </button>
                </div>
            </div>
        </header>
    );
}

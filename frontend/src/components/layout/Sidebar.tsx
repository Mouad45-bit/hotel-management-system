"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
    BedDouble,
    Building2,
    CalendarDays,
    FileText,
    LayoutDashboard,
    Settings,
    Sparkles,
    UserRound,
    UsersRound,
    type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface NavigationItem {
    name: string;
    href: string;
    icon: LucideIcon;
    disabled: boolean;
}

const navigation: NavigationItem[] = [
    { name: "Vue générale", href: "/", icon: LayoutDashboard, disabled: false },
    { name: "Chambres", href: "/rooms", icon: BedDouble, disabled: false },
    { name: "Clients", href: "#", icon: UsersRound, disabled: true },
    { name: "Réservations", href: "#", icon: CalendarDays, disabled: true },
    { name: "Factures", href: "/invoices", icon: FileText, disabled: false },
    { name: "Housekeeping", href: "/housekeeping", icon: Sparkles, disabled: false },
    { name: "Paramètres", href: "#", icon: Settings, disabled: true },
];

export function Sidebar() {
    const pathname = usePathname();

    return (
        <aside className="fixed inset-y-0 left-0 hidden w-[320px] border-r border-[var(--hms-soft-border)] bg-white lg:block">
            <div className="flex h-28 items-center gap-4 border-b border-[var(--hms-soft-border)] px-8">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-white">
                    <Building2 aria-hidden="true" className="h-6 w-6" strokeWidth={1.8} />
                </div>

                <div>
                    <p className="text-lg font-extrabold tracking-tight text-[var(--hms-text)]">HMS</p>
                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">Gérez votre hôtel avec clarté</p>
                </div>
            </div>

            <nav className="space-y-2 px-5 py-7">
                {navigation.map((item) => {
                    const Icon = item.icon;
                    const active =
                        item.href !== "#" &&
                        (pathname === item.href ||
                            pathname.startsWith(`${item.href}/`));

                    if (item.disabled) {
                        return (
                            <span
                                key={item.name}
                                className="flex cursor-not-allowed items-center justify-between gap-3 rounded-2xl px-4 py-3 text-sm font-semibold text-[rgba(13,9,7,0.36)]"
                            >
                                <span className="flex items-center gap-3">
                                    <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                                    {item.name}
                                </span>
                                <span className="rounded-full border border-[var(--hms-soft-border)] px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                    Bientôt
                                </span>
                            </span>
                        );
                    }

                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={cn(
                                "flex cursor-pointer items-center gap-3 rounded-2xl px-4 py-3 text-sm font-semibold transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2",
                                active
                                    ? "bg-[var(--hms-primary)] text-white"
                                    : "text-[var(--hms-text-muted)] hover:bg-slate-50 hover:text-[var(--hms-text)]"
                            )}
                        >
                            <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                            {item.name}
                        </Link>
                    );
                })}
            </nav>

            <div className="absolute bottom-6 left-5 right-5 rounded-[20px] border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-white text-[var(--hms-primary)] shadow-sm">
                        <UserRound aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div className="min-w-0">
                        <p className="truncate text-sm font-bold text-[var(--hms-text)]">Réception HMS</p>
                        <p className="mt-0.5 text-xs text-[var(--hms-text-muted)]">Session locale</p>
                    </div>
                </div>
            </div>
        </aside>
    );
}

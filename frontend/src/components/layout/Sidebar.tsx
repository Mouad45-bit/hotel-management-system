"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
    BedDouble,
    Building2,
    CalendarDays,
    FileText,
    LayoutGrid,
    LogOut,
    Shield,
    Sparkles,
    UserRoundCog,
    Users,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/contexts/AuthContext";

const navigation = [
    { name: "Accueil", href: "/", icon: LayoutGrid },
    { name: "Chambres", href: "/rooms", icon: BedDouble, soon: false },
    { name: "Clients", href: "/clients", icon: Users, soon: false },
    { name: "Réservations", href: "/reservations", icon: CalendarDays, soon: false },
    { name: "Factures", href: "/invoices", icon: FileText, soon: false },
    { name: "Housekeeping", href: "/housekeeping", icon: Sparkles, soon: false },
    { name: "Personnel", href: "/staff", icon: UserRoundCog, soon: false },
    { name: "Comptes système", href: "/users", icon: Shield, soon: false, adminOnly: true },
];

export function Sidebar() {
    const pathname = usePathname();
    const { user, logout } = useAuth();

    return (
        <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-[var(--hms-border)] bg-[var(--hms-surface)] lg:flex lg:flex-col">
            <Link href="/" className="flex cursor-pointer items-center gap-3 px-6 py-6">
                <div className="flex h-[52px] w-[52px] items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-white shadow-sm">
                    <Building2 className="h-7 w-7" strokeWidth={1.75} />
                </div>
                <div>
                    <p className="text-xl font-extrabold leading-none tracking-wide text-[var(--hms-text)]">HMS</p>
                </div>
            </Link>

            <nav className="flex-1 space-y-1 px-3 py-2">
                {navigation
                    .filter((item) => !("adminOnly" in item && item.adminOnly) || user?.role === "ADMIN")
                    .map((item) => {
                        const Icon = item.icon;
                        const active = item.href !== "#" && pathname.startsWith(item.href) && item.href !== "/";
                        const isRoot = item.href === "/" && pathname === "/";

                        return (
                            <Link
                                key={item.name}
                                href={item.href}
                                className={cn(
                                    "flex cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors duration-150",
                                    active || isRoot
                                        ? "bg-[var(--hms-primary)] text-white shadow-sm"
                                        : "text-[var(--hms-text)] hover:bg-slate-50"
                                )}
                            >
                                <Icon className="h-5 w-5" strokeWidth={1.8} />
                                {item.name}
                            </Link>
                        );
                    })}
            </nav>

            {user && (
                <div className="border-t border-[var(--hms-border)] px-3 py-4">
                    <div className="flex items-center justify-between rounded-xl px-3 py-2">
                        <div className="min-w-0">
                            <p className="truncate text-sm font-semibold text-[var(--hms-text)]">
                                {user.firstName} {user.lastName}
                            </p>
                            <p className="truncate text-xs text-[var(--hms-text-muted)]">{user.role}</p>
                        </div>
                        <button
                            type="button"
                            onClick={logout}
                            className="ml-2 cursor-pointer rounded-xl p-2.5 text-[var(--hms-text-muted)] transition-colors hover:bg-red-50 hover:text-red-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-200 focus-visible:ring-offset-2"
                            title="Déconnexion"
                        >
                            <LogOut className="h-5 w-5" strokeWidth={1.8} />
                        </button>
                    </div>
                </div>
            )}
        </aside>
    );
}

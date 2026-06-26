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
    Users,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/contexts/AuthContext";

const navigation = [
    { name: "Vue générale", href: "/", icon: LayoutGrid, soon: true },
    { name: "Chambres", href: "/rooms", icon: BedDouble, soon: false },
    { name: "Clients", href: "/clients", icon: Users, soon: false },
    { name: "Réservations", href: "/reservations", icon: CalendarDays, soon: false },
    { name: "Factures", href: "#", icon: FileText, soon: true },
    { name: "Housekeeping", href: "#", icon: Sparkles, soon: true },
    { name: "Utilisateurs", href: "/users", icon: Shield, soon: false, adminOnly: true },
];

function SoonBadge() {
    return (
        <span className="ml-auto rounded-full bg-zinc-100 px-2 py-0.5 text-[11px] font-medium text-zinc-500">
            Bientôt
        </span>
    );
}

export function Sidebar() {
    const pathname = usePathname();
    const { user, logout } = useAuth();

    return (
        <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-zinc-200 bg-white lg:flex lg:flex-col">
            <Link
                href="/"
                className="flex items-center gap-3 px-6 py-6"
            >
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-zinc-900 text-white">
                    <Building2 className="h-6 w-6" />
                </div>

                <div>
                    <p className="text-lg font-bold leading-tight text-zinc-950">HMS</p>
                    <p className="text-xs leading-tight text-zinc-500">
                        Gérez votre hôtel avec clarté
                    </p>
                </div>
            </Link>

            <nav className="flex-1 space-y-1 px-3 py-2">
                {navigation.filter((item) => !('adminOnly' in item && item.adminOnly) || user?.role === 'ADMIN').map((item) => {
                    const Icon = item.icon;
                    const active = item.href !== "#" && pathname.startsWith(item.href) && item.href !== "/";
                    const isRoot = item.href === "/" && pathname === "/";

                    if (item.soon) {
                        return (
                            <span
                                key={item.name}
                                className="flex cursor-not-allowed items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-zinc-400"
                            >
                                <Icon className="h-5 w-5" />
                                {item.name}
                                <SoonBadge />
                            </span>
                        );
                    }

                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={cn(
                                "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition",
                                active || isRoot
                                    ? "bg-zinc-900 text-white shadow-sm"
                                    : "text-zinc-700 hover:bg-zinc-100 hover:text-zinc-950"
                            )}
                        >
                            <Icon className="h-5 w-5" />
                            {item.name}
                        </Link>
                    );
                })}
            </nav>

            {user && (
                <div className="border-t border-zinc-200 px-3 py-4">
                    <div className="flex items-center justify-between rounded-xl px-3 py-2">
                        <div className="min-w-0">
                            <p className="truncate text-sm font-semibold text-zinc-900">{user.firstName} {user.lastName}</p>
                            <p className="truncate text-xs text-zinc-500">{user.role}</p>
                        </div>
                        <button
                            onClick={logout}
                            className="ml-2 rounded-lg p-1.5 text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-700"
                            title="Déconnexion"
                        >
                            <LogOut className="h-4 w-4" />
                        </button>
                    </div>
                </div>
            )}
        </aside>
    );
}

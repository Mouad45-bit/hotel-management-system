"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
    BuildingOffice2Icon,
    CalendarDaysIcon,
    Cog6ToothIcon,
    DocumentTextIcon,
    HomeIcon,
    Squares2X2Icon,
    SparklesIcon,
    UsersIcon,
    ChevronLeftIcon,
    ChevronRightIcon,
} from "@heroicons/react/24/outline";
import { cn } from "@/lib/utils";

const navigation = [
    { name: "Dashboard", href: "/", icon: Squares2X2Icon, disabled: false },
    { name: "Chambres", href: "/rooms", icon: BuildingOffice2Icon, disabled: false },
    { name: "Clients", href: "#", icon: UsersIcon, disabled: true },
    { name: "Réservations", href: "#", icon: CalendarDaysIcon, disabled: true },
    { name: "Factures", href: "#", icon: DocumentTextIcon, disabled: true },
    { name: "Paramètres", href: "#", icon: Cog6ToothIcon, disabled: true },
];

interface SidebarProps {
    collapsed: boolean;
    onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
    const pathname = usePathname();

    return (
        <aside
            className={cn(
                "fixed inset-y-0 left-0 hidden border-r border-zinc-200 bg-white lg:block transition-all duration-300",
                collapsed ? "w-20" : "w-64"
            )}
        >
            {/* ─── En-tête ────────────────────────────────────────────── */}
            <div className="flex h-16 items-center border-b border-zinc-200 px-4">
                <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-2xl bg-stone-900 text-white">
                    <HomeIcon className="h-5 w-5" />
                </div>

                {!collapsed && (
                    <div className="ml-3 overflow-hidden">
                        <p className="text-sm font-bold text-zinc-950">HMS</p>
                        <p className="text-xs text-zinc-500">Hotel Management</p>
                    </div>
                )}
            </div>

            {/* ─── Navigation ─────────────────────────────────────────── */}
            <nav className="space-y-1 px-3 py-4">
                {navigation.map((item) => {
                    const Icon = item.icon;
                    const active = item.href !== "#" && pathname === item.href;

                    if (item.disabled) {
                        return (
                            <span
                                key={item.name}
                                title={collapsed ? item.name : undefined}
                                className={cn(
                                    "flex cursor-not-allowed items-center rounded-xl text-sm font-medium text-zinc-400",
                                    collapsed
                                        ? "justify-center px-2 py-2"
                                        : "gap-3 px-3 py-2"
                                )}
                            >
                                <Icon className="h-5 w-5 flex-shrink-0" />
                                {!collapsed && item.name}
                            </span>
                        );
                    }

                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            title={collapsed ? item.name : undefined}
                            className={cn(
                                "flex items-center rounded-xl text-sm font-medium transition",
                                collapsed
                                    ? "justify-center px-2 py-2"
                                    : "gap-3 px-3 py-2",
                                active
                                    ? "bg-stone-900 text-white"
                                    : "text-zinc-700 hover:bg-stone-50 hover:text-stone-950"
                            )}
                        >
                            <Icon className="h-5 w-5 flex-shrink-0" />
                            {!collapsed && item.name}
                        </Link>
                    );
                })}
            </nav>

            {/* ─── Carte Sprint (masquée en mode réduit) ──────────────── */}
            {!collapsed && (
                <div className="absolute bottom-16 left-3 right-3 rounded-2xl border border-stone-200 bg-stone-50 p-4">
                    <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-stone-900">
                        <SparklesIcon className="h-4 w-4" />
                        Sprint 4
                    </div>
                    <p className="text-xs leading-5 text-stone-600">
                        Module Chambres en cours de préparation pour la première démo.
                    </p>
                </div>
            )}

            {/* ─── Bouton toggle en bas ────────────────────────────────── */}
            <button
                onClick={onToggle}
                className={cn(
                    "absolute bottom-4 flex items-center justify-center rounded-xl border border-zinc-200 bg-zinc-50 p-2 text-zinc-500 hover:bg-zinc-100 hover:text-zinc-900 transition-colors",
                    collapsed ? "left-3 right-3" : "left-3 right-3"
                )}
                title={collapsed ? "Agrandir la sidebar" : "Réduire la sidebar"}
            >
                {collapsed
                    ? <ChevronRightIcon className="h-4 w-4" />
                    : <ChevronLeftIcon className="h-4 w-4" />
                }
                {!collapsed && (
                    <span className="ml-2 text-xs font-medium">Réduire</span>
                )}
            </button>
        </aside>
    );
}

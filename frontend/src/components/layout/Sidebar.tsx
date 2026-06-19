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
} from "@heroicons/react/24/outline";
import { cn } from "@/lib/utils";

const navigation = [
    { name: "Dashboard", href: "/", icon: Squares2X2Icon, disabled: false },
    { name: "Chambres", href: "/rooms", icon: BuildingOffice2Icon, disabled: false },
    { name: "Clients", href: "#", icon: UsersIcon, disabled: true },
    { name: "Réservations", href: "#", icon: CalendarDaysIcon, disabled: true },
    { name: "Factures", href: "/invoices", icon: DocumentTextIcon, disabled: false },
    { name: "Housekeeping", href: "/housekeeping", icon: SparklesIcon, disabled: false },
    { name: "Paramètres", href: "#", icon: Cog6ToothIcon, disabled: true },
];

export function Sidebar() {
    const pathname = usePathname();

    return (
        <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-zinc-200 bg-white lg:block">
            <div className="flex h-16 items-center gap-3 border-b border-zinc-200 px-6">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-stone-900 text-white">
                    <HomeIcon className="h-5 w-5" />
                </div>

                <div>
                    <p className="text-sm font-bold text-zinc-950">HMS</p>
                    <p className="text-xs text-zinc-500">Hotel Management</p>
                </div>
            </div>

            <nav className="space-y-1 px-3 py-4">
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
                                className="flex cursor-not-allowed items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium text-zinc-400"
                            >
                                <Icon className="h-5 w-5" />
                                {item.name}
                            </span>
                        );
                    }

                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={cn(
                                "flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition",
                                active
                                    ? "bg-stone-900 text-white"
                                    : "text-zinc-700 hover:bg-stone-50 hover:text-stone-950"
                            )}
                        >
                            <Icon className="h-5 w-5" />
                            {item.name}
                        </Link>
                    );
                })}
            </nav>

            <div className="absolute bottom-4 left-3 right-3 rounded-2xl border border-stone-200 bg-stone-50 p-4">
                <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-stone-900">
                    <SparklesIcon className="h-4 w-4" />
                    Démo locale
                </div>

                <p className="text-xs leading-5 text-stone-600">
                    Modules visibles : Chambres, Factures et Housekeeping. Les
                    autres modules seront activés progressivement.
                </p>
            </div>
        </aside>
    );
}

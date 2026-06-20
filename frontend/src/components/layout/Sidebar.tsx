"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
    BedDouble,
    Building2,
    CalendarDays,
    FileText,
    LayoutGrid,
    Sparkles,
    Users,
} from "lucide-react";
import { cn } from "@/lib/utils";

const navigation = [
    { name: "Vue générale", href: "/", icon: LayoutGrid, soon: true },
    { name: "Chambres", href: "/rooms", icon: BedDouble, soon: false },
    { name: "Clients", href: "/clients", icon: Users, soon: false },
    { name: "Réservations", href: "#", icon: CalendarDays, soon: true },
    { name: "Factures", href: "#", icon: FileText, soon: true },
    { name: "Housekeeping", href: "#", icon: Sparkles, soon: true },
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

    return (
        <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-zinc-200 bg-white lg:block">
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

            <nav className="space-y-1 px-3 py-2">
                {navigation.map((item) => {
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
        </aside>
    );
}

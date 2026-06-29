"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
    BedDouble,
    CalendarDays,
    CalendarPlus,
    CircleDot,
    ClipboardList,
    FileText,
    LayoutGrid,
    ListPlus,
    Play,
    Plus,
    Shield,
    Sparkles,
    UserPlus,
    UserRoundCog,
    Users,
} from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { AppLayout } from "@/components/layout/AppLayout";
import { useAuth } from "@/contexts/AuthContext";
import { getQuickAccessForRole, getRoleLabel } from "@/lib/rbac";

const ICONS = {
    BedDouble,
    CalendarDays,
    CalendarPlus,
    CircleDot,
    ClipboardList,
    FileText,
    LayoutGrid,
    ListPlus,
    Play,
    Plus,
    Shield,
    Sparkles,
    UserPlus,
    UserRoundCog,
    Users,
};

export default function HomePage() {
    const { user } = useAuth();
    const searchParams = useSearchParams();
    const quickAccess = getQuickAccessForRole(user?.role);
    const hasUnauthorizedMessage = searchParams.get("unauthorized") === "1";

    return (
        <AppLayout>
            <div className="space-y-6">
                {hasUnauthorizedMessage && (
                    <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-800">
                        Accès non autorisé. Vous avez été redirigé vers votre accueil.
                    </div>
                )}

                <div className="flex flex-col gap-4 rounded-3xl bg-white p-6 shadow-sm ring-1 ring-inset ring-[var(--hms-soft-border)] sm:flex-row sm:items-start sm:justify-between">
                    <div>
                        <p className="text-sm font-medium text-[var(--hms-text-muted)]">Accueil</p>
                        <h1 className="mt-2 text-3xl font-extrabold tracking-tight text-[var(--hms-text)]">
                            Bienvenue {user?.firstName} {user?.lastName}
                        </h1>
                    </div>

                    <span className="inline-flex w-fit items-center rounded-full bg-slate-50 px-3 py-1 text-xs font-semibold text-[var(--hms-text)] ring-1 ring-inset ring-[var(--hms-soft-border)]">
                        {getRoleLabel(user?.role)}
                    </span>
                </div>

                <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
                    {quickAccess.map((item) => {
                        const Icon = ICONS[item.icon as keyof typeof ICONS] ?? LayoutGrid;

                        return (
                            <Link key={item.href} href={item.href} className="block">
                                <HmsCard className="h-full transition hover:-translate-y-0.5 hover:shadow-md">
                                    <div className="flex items-start gap-4">
                                        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-white shadow-sm">
                                            <Icon className="h-5 w-5" strokeWidth={1.8} />
                                        </div>
                                        <div>
                                            <h2 className="text-base font-bold text-[var(--hms-text)]">
                                                {item.title}
                                            </h2>
                                            <p className="mt-2 text-sm leading-6 text-[var(--hms-text-muted)]">
                                                {item.description}
                                            </p>
                                        </div>
                                    </div>
                                </HmsCard>
                            </Link>
                        );
                    })}
                </div>
            </div>
        </AppLayout>
    );
}

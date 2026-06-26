"use client";

import {
    CircleCheckBig,
    Link2,
    UserRoundX,
    UsersRound,
    type LucideIcon,
} from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { cn } from "@/lib/utils";
import { formatEmployeeCount, type StaffStats } from "@/types/staff";

interface StaffStatsCardsProps {
    stats: StaffStats;
    loading?: boolean;
}

interface StatCard {
    label: string;
    value: string;
    description: string;
    icon: LucideIcon;
    tone: "default" | "success" | "warning" | "info";
}

const TONE_CLASSES: Record<StatCard["tone"], string> = {
    default: "bg-zinc-100 text-zinc-700",
    success: "bg-emerald-50 text-emerald-700",
    warning: "bg-red-50 text-red-700",
    info: "bg-blue-50 text-blue-700",
};

export function StaffStatsCards({ stats, loading = false }: StaffStatsCardsProps) {
    const cards: StatCard[] = [
        {
            label: "Total employés",
            value: formatEmployeeCount(stats.total),
            description: "Tous les départements opérationnels",
            icon: UsersRound,
            tone: "default",
        },
        {
            label: "Actifs",
            value: formatEmployeeCount(stats.active),
            description: "Disponibles pour l’activité hôtel",
            icon: CircleCheckBig,
            tone: "success",
        },
        {
            label: "Désactivés",
            value: formatEmployeeCount(stats.inactive),
            description: "Non affectables aux opérations",
            icon: UserRoundX,
            tone: "warning",
        },
        {
            label: "Comptes liés",
            value: formatEmployeeCount(stats.linked),
            description: "Employés liés à un utilisateur système",
            icon: Link2,
            tone: "info",
        },
    ];

    return (
        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
            {cards.map((card) => {
                const Icon = card.icon;

                return (
                    <HmsCard key={card.label} className="p-6">
                        <div className="flex items-start justify-between gap-4">
                            <div>
                                <p className="text-sm font-medium text-[var(--hms-text-muted)]">
                                    {card.label}
                                </p>
                                <div className="mt-2">
                                    {loading ? (
                                        <div className="h-7 w-24 animate-pulse rounded-lg bg-zinc-100" />
                                    ) : (
                                        <p className="text-2xl font-bold tracking-tight text-[var(--hms-text)]">
                                            {card.value}
                                        </p>
                                    )}
                                </div>
                                <p className="mt-2 text-xs leading-5 text-[var(--hms-text-muted)]">
                                    {card.description}
                                </p>
                            </div>

                            <div className={cn("flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl", TONE_CLASSES[card.tone])}>
                                <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                            </div>
                        </div>
                    </HmsCard>
                );
            })}
        </div>
    );
}

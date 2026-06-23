"use client";

import type { ComponentType, SVGProps } from "react";
import {
    CheckCircleIcon,
    ClipboardDocumentListIcon,
    ClockIcon,
    ExclamationTriangleIcon,
    NoSymbolIcon,
    UserMinusIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { cn } from "@/lib/utils";
import type { HousekeepingStats } from "@/types/housekeeping";

type StatIcon = ComponentType<SVGProps<SVGSVGElement>>;

interface HousekeepingStatsCardsProps {
    stats: HousekeepingStats;
    loading?: boolean;
}

interface StatCard {
    label: string;
    value: number;
    description: string;
    icon: StatIcon;
    tone: "default" | "info" | "success" | "danger" | "warning";
}

const TONE_CLASSES: Record<StatCard["tone"], string> = {
    default: "bg-zinc-100 text-zinc-700",
    info: "bg-blue-50 text-blue-700",
    success: "bg-emerald-50 text-emerald-700",
    danger: "bg-red-50 text-red-700",
    warning: "bg-orange-50 text-orange-700",
};

export function HousekeepingStatsCards({
    stats,
    loading = false,
}: HousekeepingStatsCardsProps) {
    const cards: StatCard[] = [
        {
            label: "Total tâches",
            value: stats.total,
            description: `${stats.todo} à faire, ${stats.inProgress} en cours`,
            icon: ClipboardDocumentListIcon,
            tone: "default",
        },
        {
            label: "À faire",
            value: stats.todo,
            description: "Tâches en attente de démarrage",
            icon: ClockIcon,
            tone: "info",
        },
        {
            label: "Terminées",
            value: stats.done,
            description: `${stats.cancelled} tâche(s) annulée(s)`,
            icon: CheckCircleIcon,
            tone: "success",
        },
        {
            label: "Urgentes",
            value: stats.urgent,
            description: `${stats.unassigned} tâche(s) non assignée(s)`,
            icon: ExclamationTriangleIcon,
            tone: "warning",
        },
        {
            label: "En cours",
            value: stats.inProgress,
            description: "Chambres temporairement indisponibles",
            icon: UserMinusIcon,
            tone: "info",
        },
        {
            label: "Annulées",
            value: stats.cancelled,
            description: "Statut final sans suppression physique",
            icon: NoSymbolIcon,
            tone: "danger",
        },
    ];

    return (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {cards.map((card) => {
                const Icon = card.icon;

                return (
                    <HmsCard key={card.label}>
                        <div className="flex items-start justify-between gap-4">
                            <div>
                                <p className="text-sm text-zinc-500">
                                    {card.label}
                                </p>

                                <div className="mt-2">
                                    {loading ? (
                                        <div className="h-7 w-16 animate-pulse rounded-lg bg-zinc-100" />
                                    ) : (
                                        <p className="text-2xl font-semibold text-zinc-950">
                                            {card.value}
                                        </p>
                                    )}
                                </div>

                                <p className="mt-2 text-xs text-zinc-500">
                                    {card.description}
                                </p>
                            </div>

                            <div
                                className={cn(
                                    "flex h-10 w-10 items-center justify-center rounded-2xl",
                                    TONE_CLASSES[card.tone]
                                )}
                            >
                                <Icon className="h-5 w-5" />
                            </div>
                        </div>
                    </HmsCard>
                );
            })}
        </div>
    );
}

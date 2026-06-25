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
    variant?: "default" | "dashboard";
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

function formatCount(count: number, singular: string, plural = `${singular}s`) {
    return `${count} ${count > 1 ? plural : singular}`;
}

export function HousekeepingStatsCards({
    stats,
    loading = false,
    variant = "default",
}: HousekeepingStatsCardsProps) {
    const defaultCards: StatCard[] = [
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
            description: `${formatCount(stats.cancelled, "tâche annulée", "tâches annulées")}`,
            icon: CheckCircleIcon,
            tone: "success",
        },
        {
            label: "Urgentes",
            value: stats.urgent,
            description: `${formatCount(stats.unassigned, "tâche non assignée", "tâches non assignées")}`,
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

    const dashboardCards: StatCard[] = [
        {
            label: "Tâches suivies",
            value: stats.total,
            description: `${formatCount(stats.todo, "à faire", "à faire")}, ${formatCount(stats.inProgress, "en cours", "en cours")}`,
            icon: ClipboardDocumentListIcon,
            tone: "default",
        },
        {
            label: "En cours",
            value: stats.inProgress,
            description: "Chambres temporairement indisponibles",
            icon: ClockIcon,
            tone: "info",
        },
        {
            label: "Terminées",
            value: stats.done,
            description: `${formatCount(stats.cancelled, "tâche annulée", "tâches annulées")}`,
            icon: CheckCircleIcon,
            tone: "success",
        },
        {
            label: "À traiter",
            value: stats.urgent,
            description: `${formatCount(stats.unassigned, "tâche non assignée", "tâches non assignées")}`,
            icon: ExclamationTriangleIcon,
            tone: "warning",
        },
    ];

    const cards = variant === "dashboard" ? dashboardCards : defaultCards;
    const gridClassName =
        variant === "dashboard"
            ? "grid gap-5 md:grid-cols-2 xl:grid-cols-4"
            : "grid gap-4 md:grid-cols-2 xl:grid-cols-3";

    return (
        <div className={gridClassName}>
            {cards.map((card) => {
                const Icon = card.icon;

                return (
                    <HmsCard key={card.label} className={variant === "dashboard" ? "p-6" : undefined}>
                        <div className="flex items-start justify-between gap-4">
                            <div>
                                <p className="text-sm font-medium text-[var(--hms-text-muted)]">
                                    {card.label}
                                </p>

                                <div className="mt-2">
                                    {loading ? (
                                        <div className="h-7 w-16 animate-pulse rounded-lg bg-zinc-100" />
                                    ) : (
                                        <p className="text-2xl font-bold tracking-tight text-[var(--hms-text)]">
                                            {card.value}
                                        </p>
                                    )}
                                </div>

                                <p className="mt-2 text-xs text-[var(--hms-text-muted)]">
                                    {card.description}
                                </p>
                            </div>

                            <div
                                className={cn(
                                    "flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl",
                                    TONE_CLASSES[card.tone]
                                )}
                            >
                                <Icon className="h-5 w-5" aria-hidden="true" />
                            </div>
                        </div>
                    </HmsCard>
                );
            })}
        </div>
    );
}

import { BedDouble, CheckCircle, Sparkles, User, Wrench, type LucideIcon } from "lucide-react";
import type { RoomStats } from "@/types/room";
import { HmsCard } from "@/components/hms/HmsCard";
import { cn } from "@/lib/utils";

interface RoomStatsCardsProps {
    stats: RoomStats | null;
    loading?: boolean;
}

interface StatCard {
    label: string;
    value: number;
    description: string;
    icon: LucideIcon;
    tone: "default" | "success" | "warning" | "info";
}

const TONE_CLASSES: Record<StatCard["tone"], string> = {
    default: "bg-zinc-100 text-zinc-700",
    success: "bg-emerald-50 text-emerald-700",
    warning: "bg-orange-50 text-orange-700",
    info: "bg-blue-50 text-blue-700",
};

function formatCount(count: number, singular: string, plural = `${singular}s`) {
    return `${count} ${count > 1 ? plural : singular}`;
}

function StatDescription({ description }: { description: string }) {
    const lines = description.split(", ");

    return (
        <>
            {lines.map((line, index) => (
                <span key={line} className={index > 0 ? "block" : undefined}>
                    {index < lines.length - 1 ? `${line},` : line}
                </span>
            ))}
        </>
    );
}

export function RoomStatsCards({ stats, loading = false }: RoomStatsCardsProps) {
    const cards: StatCard[] = [
        {
            label: "Total chambres",
            value: stats?.total ?? 0,
            description: `${formatCount(stats?.reserved ?? 0, "réservée", "réservées")}, ${formatCount(stats?.occupied ?? 0, "occupée", "occupées")}`,
            icon: BedDouble,
            tone: "default",
        },
        {
            label: "Disponibles",
            value: stats?.available ?? 0,
            description: "Chambres ouvertes à la réservation",
            icon: CheckCircle,
            tone: "success",
        },
        {
            label: "Occupées",
            value: stats?.occupied ?? 0,
            description: `${formatCount(stats?.reserved ?? 0, "chambre réservée", "chambres réservées")}`,
            icon: User,
            tone: "warning",
        },
        {
            label: "À préparer",
            value: (stats?.cleaning ?? 0) + (stats?.maintenance ?? 0) + (stats?.outOfService ?? 0),
            description: `${formatCount(stats?.cleaning ?? 0, "en nettoyage", "en nettoyage")}, ${formatCount(stats?.maintenance ?? 0, "en maintenance", "en maintenance")}`,
            icon: stats && stats.outOfService > 0 ? Wrench : Sparkles,
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
                                        <div className="h-7 w-16 animate-pulse rounded-lg bg-zinc-100" />
                                    ) : (
                                        <p className="text-2xl font-bold tracking-tight text-[var(--hms-text)]">
                                            {card.value}
                                        </p>
                                    )}
                                </div>

                                <p className="mt-2 text-xs text-[var(--hms-text-muted)]">
                                    <StatDescription description={card.description} />
                                </p>
                            </div>

                            <div
                                className={cn(
                                    "flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl",
                                    TONE_CLASSES[card.tone]
                                )}
                            >
                                <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                            </div>
                        </div>
                    </HmsCard>
                );
            })}
        </div>
    );
}

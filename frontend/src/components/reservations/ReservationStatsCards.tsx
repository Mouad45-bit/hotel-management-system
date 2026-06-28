import { CalendarDays, CalendarCheck, CheckCircle, LogIn, type LucideIcon } from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import type { Reservation } from "@/types/reservation";
import { cn } from "@/lib/utils";

interface ReservationStatsCardsProps {
    reservations: Reservation[];
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

export function ReservationStatsCards({ reservations, loading = false }: ReservationStatsCardsProps) {
    const total = reservations.length;
    const created = reservations.filter((r) => r.status === "CREATED").length;
    const confirmed = reservations.filter((r) => r.status === "CONFIRMED").length;
    const checkedIn = reservations.filter((r) => r.status === "CHECKED_IN").length;
    const checkedOut = reservations.filter((r) => r.status === "CHECKED_OUT").length;
    const cancelled = reservations.filter((r) => r.status === "CANCELLED").length;
    const noShow = reservations.filter((r) => r.status === "NO_SHOW").length;

    const cards: StatCard[] = [
        {
            label: "Total réservations",
            value: total,
            description: `${formatCount(created, "créée", "créées")}, ${formatCount(confirmed, "confirmée", "confirmées")}`,
            icon: CalendarDays,
            tone: "default",
        },
        {
            label: "Confirmées",
            value: confirmed,
            description: "Réservations validées à venir",
            icon: CalendarCheck,
            tone: "info",
        },
        {
            label: "En séjour",
            value: checkedIn,
            description: `${formatCount(checkedIn, "check-in", "check-ins")} en cours`,
            icon: LogIn,
            tone: "warning",
        },
        {
            label: "Clôturées",
            value: checkedOut,
            description: `${formatCount(cancelled, "annulée", "annulées")}, ${formatCount(noShow, "no-show", "no-shows")}`,
            icon: CheckCircle,
            tone: "success",
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

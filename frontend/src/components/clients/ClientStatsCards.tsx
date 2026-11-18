import { CheckCircle, IdCard, Mail, Users, type LucideIcon } from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import type { Client } from "@/types/client";
import { cn } from "@/lib/utils";

interface ClientStatsCardsProps {
    clients: Client[];
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

export function ClientStatsCards({ clients, loading = false }: ClientStatsCardsProps) {
    const total = clients.length;
    const active = clients.filter((c) => c.active !== false).length;
    const inactive = total - active;
    const withContact = clients.filter((c) => Boolean(c.email || c.phone)).length;
    const withCin = clients.filter((c) => Boolean(c.cin)).length;

    const cards: StatCard[] = [
        {
            label: "Total clients",
            value: total,
            description: `${formatCount(active, "actif", "actifs")}, ${formatCount(inactive, "désactivé", "désactivés")}`,
            icon: Users,
            tone: "default",
        },
        {
            label: "Clients actifs",
            value: active,
            description: "Fiches disponibles dans les opérations",
            icon: CheckCircle,
            tone: "success",
        },
        {
            label: "Contacts renseignés",
            value: withContact,
            description: `${formatCount(withContact, "fiche joignable", "fiches joignables")}`,
            icon: Mail,
            tone: "info",
        },
        {
            label: "Identités",
            value: withCin,
            description: `${formatCount(withCin, "CIN renseigné", "CIN renseignés")}`,
            icon: IdCard,
            tone: "warning",
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

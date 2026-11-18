"use client";

import {
    CircleCheckBig,
    Clock3,
    FileText,
    RotateCcw,
    type LucideIcon,
} from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { cn } from "@/lib/utils";
import type { InvoiceStats } from "@/types/invoice";

interface InvoiceStatsCardsProps {
    stats: InvoiceStats;
    loading?: boolean;
}

interface StatCard {
    label: string;
    value: string | number;
    description: string;
    icon: LucideIcon;
    tone: "default" | "success" | "warning" | "purple";
    amount?: number;
}

const TONE_CLASSES: Record<StatCard["tone"], string> = {
    default: "bg-zinc-100 text-zinc-700",
    success: "bg-emerald-50 text-emerald-700",
    warning: "bg-blue-50 text-blue-700",
    purple: "bg-purple-50 text-purple-700",
};

function formatCount(count: number, singular: string, plural = `${singular}s`) {
    return `${count} ${count > 1 ? plural : singular}`;
}

export function InvoiceStatsCards({
    stats,
    loading = false,
}: InvoiceStatsCardsProps) {
    const cards: StatCard[] = [
        {
            label: "Total factures",
            value: formatCount(stats.total, "facture"),
            description: `${formatCount(stats.draft, "brouillon")}, ${formatCount(stats.issued, "émise", "émises")}`,
            icon: FileText,
            tone: "default",
        },
        {
            label: "Chiffre encaissé",
            value: "",
            description: formatCount(stats.paid, "facture payée", "factures payées"),
            icon: CircleCheckBig,
            tone: "success",
            amount: stats.totalRevenue,
        },
        {
            label: "Montant en attente",
            value: "",
            description: formatCount(stats.issued, "facture à payer", "factures à payer"),
            icon: Clock3,
            tone: "warning",
            amount: stats.pendingAmount,
        },
        {
            label: "Remboursements",
            value: "",
            description: formatCount(stats.refunded, "facture remboursée", "factures remboursées"),
            icon: RotateCcw,
            tone: "purple",
            amount: stats.refundedAmount,
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
                                    ) : card.amount !== undefined ? (
                                        <InvoiceAmount
                                            amount={card.amount}
                                            variant="strong"
                                            className="text-2xl"
                                        />
                                    ) : (
                                        <p className="text-2xl font-bold text-[var(--hms-text)]">
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
                                <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                            </div>
                        </div>
                    </HmsCard>
                );
            })}
        </div>
    );
}

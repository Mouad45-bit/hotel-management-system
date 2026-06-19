"use client";

import type { ComponentType, SVGProps } from "react";
import {
    ArrowPathIcon,
    BanknotesIcon,
    ClockIcon,
    DocumentTextIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { cn } from "@/lib/utils";
import type { InvoiceStats } from "@/types/invoice";

type StatIcon = ComponentType<SVGProps<SVGSVGElement>>;

interface InvoiceStatsCardsProps {
    stats: InvoiceStats;
    loading?: boolean;
}

interface StatCard {
    label: string;
    value: string | number;
    description: string;
    icon: StatIcon;
    tone: "default" | "success" | "warning" | "purple";
    amount?: number;
}

const TONE_CLASSES: Record<StatCard["tone"], string> = {
    default: "bg-zinc-100 text-zinc-700",
    success: "bg-emerald-50 text-emerald-700",
    warning: "bg-blue-50 text-blue-700",
    purple: "bg-purple-50 text-purple-700",
};

export function InvoiceStatsCards({
    stats,
    loading = false,
}: InvoiceStatsCardsProps) {
    const cards: StatCard[] = [
        {
            label: "Total factures",
            value: stats.total,
            description: `${stats.draft} brouillon(s), ${stats.issued} émise(s)`,
            icon: DocumentTextIcon,
            tone: "default",
        },
        {
            label: "Chiffre encaissé",
            value: "",
            description: `${stats.paid} facture(s) payée(s)`,
            icon: BanknotesIcon,
            tone: "success",
            amount: stats.totalRevenue,
        },
        {
            label: "Montant en attente",
            value: "",
            description: `${stats.issued} facture(s) à payer`,
            icon: ClockIcon,
            tone: "warning",
            amount: stats.pendingAmount,
        },
        {
            label: "Remboursements",
            value: "",
            description: `${stats.refunded} facture(s) remboursée(s)`,
            icon: ArrowPathIcon,
            tone: "purple",
            amount: stats.refundedAmount,
        },
    ];

    return (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
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
                                        <div className="h-7 w-24 animate-pulse rounded-lg bg-zinc-100" />
                                    ) : card.amount !== undefined ? (
                                        <InvoiceAmount
                                            amount={card.amount}
                                            variant="strong"
                                            className="text-2xl"
                                        />
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

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

export interface ClientInvoiceSummary {
    totalInvoices: number;
    paidInvoices: number;
    issuedInvoices: number;
    refundedInvoices: number;
    totalRevenue: number;
    pendingAmount: number;
    refundedAmount: number;
}

interface ClientInvoiceSummaryCardsProps {
    summary: ClientInvoiceSummary;
    loading?: boolean;
}

export function ClientInvoiceSummaryCards({
    summary,
    loading = false,
}: ClientInvoiceSummaryCardsProps) {
    const cards: {
        label: string;
        description: string;
        icon: LucideIcon;
        tone: "default" | "success" | "pending" | "refunded";
        count?: number;
        amount?: number;
        amountClassName?: string;
    }[] = [
        {
            label: "Total factures",
            description: "Toutes les factures du client",
            icon: FileText,
            tone: "default",
            count: summary.totalInvoices,
        },
        {
            label: "Chiffre payé",
            description: `${summary.paidInvoices} facture(s) payée(s)`,
            icon: CircleCheckBig,
            tone: "success",
            amount: summary.totalRevenue,
        },
        {
            label: "En attente",
            description: `${summary.issuedInvoices} facture(s) émise(s)`,
            icon: Clock3,
            tone: "pending",
            amount: summary.pendingAmount,
            amountClassName: "text-blue-700",
        },
        {
            label: "Remboursé",
            description: `${summary.refundedInvoices} facture(s) remboursée(s)`,
            icon: RotateCcw,
            tone: "refunded",
            amount: summary.refundedAmount,
            amountClassName: "text-purple-700",
        },
    ];

    const toneClasses: Record<(typeof cards)[number]["tone"], string> = {
        default: "bg-slate-100 text-[var(--hms-text-muted)]",
        success: "bg-emerald-50 text-emerald-700",
        pending: "bg-blue-50 text-blue-700",
        refunded: "bg-purple-50 text-purple-700",
    };

    return (
        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
            {cards.map((card) => {
                const Icon = card.icon;

                return (
                    <HmsCard key={card.label} className="p-6">
                        <div className="flex items-start justify-between gap-4">
                            <div className="min-w-0">
                                <p className="text-sm font-medium text-[var(--hms-text-muted)]">
                                    {card.label}
                                </p>

                                <div className="mt-2">
                                    {loading ? (
                                        <div className="h-8 w-28 animate-pulse rounded-lg bg-slate-100" />
                                    ) : card.amount !== undefined ? (
                                        <InvoiceAmount
                                            amount={card.amount}
                                            variant={
                                                card.tone === "success"
                                                    ? "success"
                                                    : "strong"
                                            }
                                            className={cn(
                                                "block text-2xl tracking-tight",
                                                card.amountClassName
                                            )}
                                        />
                                    ) : (
                                        <p className="text-2xl font-bold tracking-tight text-[var(--hms-text)]">
                                            {card.count}
                                        </p>
                                    )}
                                </div>

                                <p className="mt-2 text-xs leading-5 text-[var(--hms-text-muted)]">
                                    {card.description}
                                </p>
                            </div>

                            <div
                                className={cn(
                                    "flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl",
                                    toneClasses[card.tone]
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

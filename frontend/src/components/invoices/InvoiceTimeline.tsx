"use client";

import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import type { Invoice } from "@/types/invoice";

interface InvoiceTimelineProps {
    invoice: Invoice;
}

interface TimelineItem {
    label: string;
    date?: string | null;
    description: string;
}

export function InvoiceTimeline({ invoice }: InvoiceTimelineProps) {
    const items: TimelineItem[] = [
        {
            label: "Création",
            date: invoice.createdAt,
            description: "La facture a été générée.",
        },
        {
            label: "Émission",
            date: invoice.issuedAt,
            description: "La facture a été validée et émise.",
        },
        {
            label: "Paiement",
            date: invoice.paidAt,
            description: "La facture a été marquée comme payée.",
        },
        {
            label: "Annulation",
            date: invoice.cancelledAt,
            description: "La facture a été annulée avec motif.",
        },
        {
            label: "Remboursement",
            date: invoice.refundedAt,
            description: "La facture payée a été remboursée.",
        },
    ];

    return (
        <HmsCard className="p-6">
            <h3 className="text-lg font-bold text-[var(--hms-text)]">
                Historique
            </h3>

            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                Suivi des dates importantes de la facture.
            </p>

            <div className="mt-6">
                {items.map((item, index) => {
                    const isDone = Boolean(item.date);
                    const isLast = index === items.length - 1;

                    return (
                        <div
                            key={item.label}
                            className="flex gap-3 pb-5 last:pb-0"
                        >
                            <div className="relative flex w-4 shrink-0 justify-center">
                                <div
                                    className={
                                        isDone
                                            ? "relative z-10 mt-1 h-3 w-3 rounded-full bg-emerald-600 ring-4 ring-emerald-50"
                                            : "relative z-10 mt-1 h-3 w-3 rounded-full bg-slate-300 ring-4 ring-slate-50"
                                    }
                                />

                                {!isLast && (
                                    <div
                                        className={
                                            isDone
                                                ? "absolute bottom-[-4px] top-4 w-px bg-emerald-200"
                                                : "absolute bottom-[-4px] top-4 w-px bg-[var(--hms-soft-border)]"
                                        }
                                    />
                                )}
                            </div>

                            <div className="min-w-0 flex-1">
                                <p
                                    className={
                                        isDone
                                            ? "text-sm font-semibold text-[var(--hms-text)]"
                                            : "text-sm font-medium text-[rgba(13,9,7,0.42)]"
                                    }
                                >
                                    {item.label}
                                </p>

                                <p className="mt-1">
                                    <InvoiceDate
                                        value={item.date}
                                        withTime
                                        placeholder="Non effectuée"
                                        className={
                                            isDone
                                                ? "text-xs text-[var(--hms-text-muted)]"
                                                : "text-xs text-[rgba(13,9,7,0.38)]"
                                        }
                                    />
                                </p>

                                <p
                                    className={
                                        isDone
                                            ? "mt-1 text-xs leading-5 text-[var(--hms-text-muted)]"
                                            : "mt-1 text-xs leading-5 text-[rgba(13,9,7,0.42)]"
                                    }
                                >
                                    {item.description}
                                </p>
                            </div>
                        </div>
                    );
                })}
            </div>
        </HmsCard>
    );
}

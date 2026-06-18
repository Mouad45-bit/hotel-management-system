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
        <HmsCard>
            <h3 className="text-sm font-semibold text-zinc-950">
                Historique
            </h3>

            <p className="mt-1 text-sm text-zinc-500">
                Suivi des dates importantes de la facture.
            </p>

            <div className="mt-6 space-y-5">
                {items.map((item) => {
                    const isDone = Boolean(item.date);

                    return (
                        <div key={item.label} className="flex gap-3">
                            <div className="flex flex-col items-center">
                                <div
                                    className={
                                        isDone
                                            ? "h-3 w-3 rounded-full bg-stone-900"
                                            : "h-3 w-3 rounded-full bg-zinc-200"
                                    }
                                />
                            </div>

                            <div className="-mt-1">
                                <p
                                    className={
                                        isDone
                                            ? "text-sm font-semibold text-zinc-950"
                                            : "text-sm font-medium text-zinc-400"
                                    }
                                >
                                    {item.label}
                                </p>

                                <p className="mt-1 text-xs text-zinc-500">
                                    {item.description}
                                </p>

                                <p className="mt-1">
                                    <InvoiceDate
                                        value={item.date}
                                        withTime
                                        placeholder="Non effectuée"
                                        className={
                                            isDone
                                                ? "text-xs text-zinc-600"
                                                : "text-xs text-zinc-400"
                                        }
                                    />
                                </p>
                            </div>
                        </div>
                    );
                })}
            </div>
        </HmsCard>
    );
}

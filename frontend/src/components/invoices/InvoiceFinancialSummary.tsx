"use client";

import {
    Calculator,
    Percent,
    ReceiptText,
} from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import type { Invoice } from "@/types/invoice";

interface InvoiceFinancialSummaryProps {
    invoice: Invoice;
}

export function InvoiceFinancialSummary({
    invoice,
}: InvoiceFinancialSummaryProps) {
    return (
        <HmsCard className="p-6">
            <div>
                <h3 className="text-lg font-bold text-[var(--hms-text)]">
                    Résumé financier
                </h3>

                <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                    Calcul du montant facturé pour le séjour.
                </p>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-3">
                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-5">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-[var(--hms-text-muted)]">
                        <ReceiptText aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text-muted)]">
                        Montant HT
                    </p>

                    <InvoiceAmount
                        amount={invoice.subtotalAmount}
                        variant="strong"
                        className="mt-2 block text-2xl tracking-tight"
                    />

                    <p className="mt-2 text-xs text-[var(--hms-text-muted)]">
                        Montant avant application de la taxe
                    </p>
                </div>

                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-5">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-[var(--hms-text-muted)]">
                        <Percent aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text-muted)]">
                        Taxe
                    </p>

                    <InvoiceAmount
                        amount={invoice.taxAmount}
                        variant="strong"
                        className="mt-2 block text-2xl tracking-tight"
                    />

                    <p className="mt-2 text-xs text-[var(--hms-text-muted)]">
                        Taux appliqué : {invoice.taxRate}%
                    </p>
                </div>

                <div className="rounded-2xl border border-[var(--hms-border)] bg-slate-100 p-5">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-[var(--hms-text)]">
                        <Calculator aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">
                        Total TTC
                    </p>

                    <InvoiceAmount
                        amount={invoice.totalAmount}
                        variant="strong"
                        className="mt-2 block text-3xl tracking-tight"
                    />

                    <p className="mt-2 text-xs text-[var(--hms-text-muted)]">
                        Montant final de la facture
                    </p>
                </div>
            </div>

            <div className="mt-6 grid gap-5 border-t border-[var(--hms-soft-border)] pt-5 md:grid-cols-3">
                <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Nombre de nuits
                    </p>

                    <p className="mt-2 text-sm font-semibold text-[var(--hms-text)]">
                        {invoice.nights} nuit(s)
                    </p>
                </div>

                <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Prix par nuit
                    </p>

                    <InvoiceAmount
                        amount={invoice.pricePerNight}
                        variant="default"
                        className="mt-2 block text-sm"
                    />
                </div>

                <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Formule
                    </p>

                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                        {invoice.nights} ×{" "}
                        <InvoiceAmount
                            amount={invoice.pricePerNight}
                            variant="muted"
                            className="text-sm"
                        />
                    </p>
                </div>
            </div>
        </HmsCard>
    );
}

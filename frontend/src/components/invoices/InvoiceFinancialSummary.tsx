"use client";

import {
    BanknotesIcon,
    CalculatorIcon,
    ReceiptPercentIcon,
} from "@heroicons/react/24/outline";
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
        <HmsCard>
            <div className="flex items-start justify-between gap-4">
                <div>
                    <p className="text-sm font-semibold text-zinc-950">
                        Résumé financier
                    </p>

                    <p className="mt-1 text-sm text-zinc-500">
                        Calcul du montant à payer pour le séjour.
                    </p>
                </div>

                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-stone-100 text-stone-700">
                    <CalculatorIcon className="h-5 w-5" />
                </div>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-3">
                <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                    <div className="flex items-center gap-2 text-sm font-medium text-zinc-600">
                        <BanknotesIcon className="h-4 w-4" />
                        Montant HT
                    </div>

                    <InvoiceAmount
                        amount={invoice.subtotalAmount}
                        variant="strong"
                        className="mt-3 block text-xl"
                    />
                </div>

                <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                    <div className="flex items-center gap-2 text-sm font-medium text-zinc-600">
                        <ReceiptPercentIcon className="h-4 w-4" />
                        Taxe
                    </div>

                    <div className="mt-3 flex items-end justify-between gap-3">
                        <InvoiceAmount
                            amount={invoice.taxAmount}
                            variant="strong"
                            className="block text-xl"
                        />

                        <span className="text-sm font-medium text-zinc-500">
                            {invoice.taxRate}%
                        </span>
                    </div>
                </div>

                <div className="rounded-2xl border border-stone-200 bg-stone-50 p-4">
                    <p className="text-sm font-medium text-stone-700">
                        Total TTC
                    </p>

                    <InvoiceAmount
                        amount={invoice.totalAmount}
                        variant="strong"
                        className="mt-3 block text-2xl text-stone-950"
                    />
                </div>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-3">
                <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                        Nombre de nuits
                    </p>

                    <p className="mt-1 text-sm font-semibold text-zinc-950">
                        {invoice.nights} nuit(s)
                    </p>
                </div>

                <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                        Prix par nuit
                    </p>

                    <InvoiceAmount
                        amount={invoice.pricePerNight}
                        variant="default"
                        className="mt-1 block text-sm"
                    />
                </div>

                <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                        Formule
                    </p>

                    <p className="mt-1 text-sm text-zinc-600">
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

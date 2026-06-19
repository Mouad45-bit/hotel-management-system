"use client";

import {
    BanknotesIcon,
    ClockIcon,
    DocumentTextIcon,
    ReceiptRefundIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";

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
}

export function ClientInvoiceSummaryCards({
    summary,
}: ClientInvoiceSummaryCardsProps) {
    return (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <HmsCard>
                <div className="flex items-start justify-between gap-4">
                    <div>
                        <p className="text-sm text-zinc-500">
                            Total factures
                        </p>

                        <p className="mt-2 text-2xl font-semibold text-zinc-950">
                            {summary.totalInvoices}
                        </p>

                        <p className="mt-1 text-xs text-zinc-500">
                            Toutes les factures du client
                        </p>
                    </div>

                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-zinc-100 text-zinc-700">
                        <DocumentTextIcon className="h-5 w-5" />
                    </div>
                </div>
            </HmsCard>

            <HmsCard>
                <div className="flex items-start justify-between gap-4">
                    <div>
                        <p className="text-sm text-zinc-500">
                            Chiffre payé
                        </p>

                        <InvoiceAmount
                            amount={summary.totalRevenue}
                            variant="success"
                            className="mt-2 block text-2xl"
                        />

                        <p className="mt-1 text-xs text-zinc-500">
                            {summary.paidInvoices} facture(s) payée(s)
                        </p>
                    </div>

                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-700">
                        <BanknotesIcon className="h-5 w-5" />
                    </div>
                </div>
            </HmsCard>

            <HmsCard>
                <div className="flex items-start justify-between gap-4">
                    <div>
                        <p className="text-sm text-zinc-500">
                            En attente
                        </p>

                        <InvoiceAmount
                            amount={summary.pendingAmount}
                            variant="strong"
                            className="mt-2 block text-2xl text-blue-700"
                        />

                        <p className="mt-1 text-xs text-zinc-500">
                            {summary.issuedInvoices} facture(s) émise(s)
                        </p>
                    </div>

                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-blue-50 text-blue-700">
                        <ClockIcon className="h-5 w-5" />
                    </div>
                </div>
            </HmsCard>

            <HmsCard>
                <div className="flex items-start justify-between gap-4">
                    <div>
                        <p className="text-sm text-zinc-500">
                            Remboursé
                        </p>

                        <InvoiceAmount
                            amount={summary.refundedAmount}
                            variant="strong"
                            className="mt-2 block text-2xl text-purple-700"
                        />

                        <p className="mt-1 text-xs text-zinc-500">
                            {summary.refundedInvoices} facture(s) remboursée(s)
                        </p>
                    </div>

                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-purple-50 text-purple-700">
                        <ReceiptRefundIcon className="h-5 w-5" />
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}

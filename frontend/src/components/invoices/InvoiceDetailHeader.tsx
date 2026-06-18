"use client";

import Link from "next/link";
import {
    ArrowLeftIcon,
    PrinterIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import { InvoiceStatusBadge } from "@/components/invoices/InvoiceStatusBadge";
import {
    canPrintInvoice,
    formatInvoicePeriod,
    formatInvoiceRoom,
} from "@/lib/invoiceHelpers";
import type { Invoice } from "@/types/invoice";

interface InvoiceDetailHeaderProps {
    invoice: Invoice;
}

export function InvoiceDetailHeader({ invoice }: InvoiceDetailHeaderProps) {
    return (
        <HmsCard>
            <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
                <div>
                    <Link
                        href="/invoices"
                        className="inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                    >
                        <ArrowLeftIcon className="h-4 w-4" />
                        Retour aux factures
                    </Link>

                    <div className="mt-5 flex flex-wrap items-center gap-3">
                        <h2 className="text-2xl font-semibold tracking-tight text-zinc-950">
                            {invoice.invoiceNumber}
                        </h2>

                        <InvoiceStatusBadge status={invoice.status} />
                    </div>

                    <p className="mt-3 max-w-3xl text-sm leading-6 text-zinc-500">
                        Facture liée à la réservation #{invoice.reservationId}, pour{" "}
                        {invoice.clientFullName}, {formatInvoiceRoom(invoice)}.
                    </p>

                    <div className="mt-4 flex flex-wrap gap-3 text-sm text-zinc-600">
                        <span>
                            Créée le{" "}
                            <InvoiceDate
                                value={invoice.createdAt}
                                withTime
                                className="text-sm text-zinc-600"
                            />
                        </span>

                        <span className="hidden text-zinc-300 sm:inline">•</span>

                        <span>{formatInvoicePeriod(invoice)}</span>
                    </div>
                </div>

                <div className="flex flex-col items-start gap-3 lg:items-end">
                    <div className="text-left lg:text-right">
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                            Montant TTC
                        </p>

                        <InvoiceAmount
                            amount={invoice.totalAmount}
                            variant="strong"
                            className="mt-1 block text-3xl"
                        />
                    </div>

                    {canPrintInvoice(invoice) && (
                        <Link
                            href={`/invoices/${invoice.id}/print`}
                            className="inline-flex items-center justify-center gap-2 rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50"
                        >
                            <PrinterIcon className="h-5 w-5" />
                            Imprimer
                        </Link>
                    )}
                </div>
            </div>
        </HmsCard>
    );
}

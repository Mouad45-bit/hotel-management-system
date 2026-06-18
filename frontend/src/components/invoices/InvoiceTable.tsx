"use client";

import Link from "next/link";
import {
    EyeIcon,
    PrinterIcon,
} from "@heroicons/react/24/outline";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import { InvoiceStatusBadge } from "@/components/invoices/InvoiceStatusBadge";
import {
    canPrintInvoice,
    formatInvoicePeriod,
    formatInvoiceRoom,
    getPaymentMethodDisplayLabel,
} from "@/lib/invoiceHelpers";
import type { Invoice } from "@/types/invoice";

interface InvoiceTableProps {
    invoices: Invoice[];
    loading?: boolean;
    emptyMessage?: string;
}

export function InvoiceTable({
    invoices,
    loading = false,
    emptyMessage = "Aucune facture trouvée.",
}: InvoiceTableProps) {
    if (loading && invoices.length === 0) {
        return (
            <div className="divide-y divide-zinc-100">
                {Array.from({ length: 5 }).map((_, index) => (
                    <div
                        key={index}
                        className="grid gap-4 px-6 py-4 md:grid-cols-6"
                    >
                        {Array.from({ length: 6 }).map((__, cellIndex) => (
                            <div
                                key={cellIndex}
                                className="h-5 animate-pulse rounded-lg bg-zinc-100"
                            />
                        ))}
                    </div>
                ))}
            </div>
        );
    }

    if (invoices.length === 0) {
        return (
            <div className="flex min-h-60 items-center justify-center px-6 py-12">
                <div className="text-center">
                    <p className="text-sm font-medium text-zinc-900">
                        {emptyMessage}
                    </p>

                    <p className="mt-1 text-sm text-zinc-500">
                        Essayez de modifier les filtres ou de générer une nouvelle
                        facture.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-zinc-200">
                <thead className="bg-zinc-50">
                    <tr>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Facture
                        </th>

                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Client
                        </th>

                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Séjour
                        </th>

                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Montant
                        </th>

                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Statut
                        </th>

                        <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Actions
                        </th>
                    </tr>
                </thead>

                <tbody className="divide-y divide-zinc-100 bg-white">
                    {invoices.map((invoice) => (
                        <tr
                            key={invoice.id}
                            className="transition hover:bg-stone-50/60"
                        >
                            <td className="whitespace-nowrap px-6 py-4">
                                <div>
                                    <p className="text-sm font-semibold text-zinc-950">
                                        {invoice.invoiceNumber}
                                    </p>

                                    <p className="mt-1 text-xs text-zinc-500">
                                        Créée le{" "}
                                        <InvoiceDate
                                            value={invoice.createdAt}
                                            withTime
                                            className="text-xs text-zinc-500"
                                        />
                                    </p>
                                </div>
                            </td>

                            <td className="whitespace-nowrap px-6 py-4">
                                <div>
                                    <p className="text-sm font-medium text-zinc-900">
                                        {invoice.clientFullName}
                                    </p>

                                    <p className="mt-1 text-xs text-zinc-500">
                                        Client #{invoice.clientId}
                                    </p>
                                </div>
                            </td>

                            <td className="min-w-64 px-6 py-4">
                                <div>
                                    <p className="text-sm font-medium text-zinc-900">
                                        {formatInvoiceRoom(invoice)}
                                    </p>

                                    <p className="mt-1 text-xs text-zinc-500">
                                        Réservation #{invoice.reservationId}
                                    </p>

                                    <p className="mt-1 text-xs text-zinc-500">
                                        {formatInvoicePeriod(invoice)}
                                    </p>
                                </div>
                            </td>

                            <td className="whitespace-nowrap px-6 py-4">
                                <div>
                                    <InvoiceAmount
                                        amount={invoice.totalAmount}
                                        variant={
                                            invoice.status === "PAID"
                                                ? "success"
                                                : invoice.status === "REFUNDED"
                                                  ? "muted"
                                                  : "strong"
                                        }
                                    />

                                    <p className="mt-1 text-xs text-zinc-500">
                                        {getPaymentMethodDisplayLabel(
                                            invoice.paymentMethod
                                        )}
                                    </p>
                                </div>
                            </td>

                            <td className="whitespace-nowrap px-6 py-4">
                                <InvoiceStatusBadge status={invoice.status} />
                            </td>

                            <td className="whitespace-nowrap px-6 py-4 text-right">
                                <div className="flex justify-end gap-2">
                                    <Link
                                        href={`/invoices/${invoice.id}`}
                                        className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 transition hover:bg-zinc-50"
                                    >
                                        <EyeIcon className="h-4 w-4" />
                                        Voir
                                    </Link>

                                    {canPrintInvoice(invoice) && (
                                        <Link
                                            href={`/invoices/${invoice.id}/print`}
                                            className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 transition hover:bg-zinc-50"
                                        >
                                            <PrinterIcon className="h-4 w-4" />
                                            Imprimer
                                        </Link>
                                    )}
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

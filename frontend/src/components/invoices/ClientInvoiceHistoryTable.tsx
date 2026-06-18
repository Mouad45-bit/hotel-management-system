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

interface ClientInvoiceHistoryTableProps {
    invoices: Invoice[];
    loading?: boolean;
}

export function ClientInvoiceHistoryTable({
    invoices,
    loading = false,
}: ClientInvoiceHistoryTableProps) {
    if (loading && invoices.length === 0) {
        return (
            <div className="divide-y divide-zinc-100">
                {Array.from({ length: 5 }).map((_, rowIndex) => (
                    <div
                        key={rowIndex}
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
                        Aucune facture pour ce client.
                    </p>

                    <p className="mt-1 text-sm text-zinc-500">
                        Les factures générées pour ce client apparaîtront ici.
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
                            Séjour
                        </th>

                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Paiement
                        </th>

                        <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Montant TTC
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
                            className="transition hover:bg-zinc-50"
                        >
                            <td className="whitespace-nowrap px-6 py-4">
                                <Link
                                    href={`/invoices/${invoice.id}`}
                                    className="text-sm font-semibold text-zinc-950 transition hover:text-stone-700"
                                >
                                    {invoice.invoiceNumber}
                                </Link>

                                <p className="mt-1 text-xs text-zinc-500">
                                    Réservation #{invoice.reservationId}
                                </p>

                                <p className="mt-1 text-xs text-zinc-500">
                                    Créée le{" "}
                                    <InvoiceDate
                                        value={invoice.createdAt}
                                        className="text-xs text-zinc-500"
                                    />
                                </p>
                            </td>

                            <td className="min-w-72 px-6 py-4">
                                <p className="text-sm font-medium text-zinc-900">
                                    {formatInvoiceRoom(invoice)}
                                </p>

                                <p className="mt-1 text-xs text-zinc-500">
                                    {formatInvoicePeriod(invoice)}
                                </p>

                                <p className="mt-1 text-xs text-zinc-500">
                                    {invoice.nights} nuit(s) ×{" "}
                                    <InvoiceAmount
                                        amount={invoice.pricePerNight}
                                        variant="muted"
                                        className="text-xs"
                                    />
                                </p>
                            </td>

                            <td className="whitespace-nowrap px-6 py-4">
                                <p className="text-sm text-zinc-700">
                                    {getPaymentMethodDisplayLabel(
                                        invoice.paymentMethod
                                    )}
                                </p>

                                <p className="mt-1 text-xs text-zinc-500">
                                    Réf. {invoice.paymentReference ?? "—"}
                                </p>

                                {invoice.paidAt && (
                                    <p className="mt-1 text-xs text-zinc-500">
                                        Payée le{" "}
                                        <InvoiceDate
                                            value={invoice.paidAt}
                                            className="text-xs text-zinc-500"
                                        />
                                    </p>
                                )}
                            </td>

                            <td className="whitespace-nowrap px-6 py-4 text-right">
                                <InvoiceAmount
                                    amount={invoice.totalAmount}
                                    variant="strong"
                                    className="text-sm"
                                />

                                <p className="mt-1 text-xs text-zinc-500">
                                    HT{" "}
                                    <InvoiceAmount
                                        amount={invoice.subtotalAmount}
                                        variant="muted"
                                        className="text-xs"
                                    />
                                </p>
                            </td>

                            <td className="whitespace-nowrap px-6 py-4">
                                <InvoiceStatusBadge status={invoice.status} />
                            </td>

                            <td className="whitespace-nowrap px-6 py-4 text-right">
                                <div className="flex items-center justify-end gap-2">
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
                                            PDF
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

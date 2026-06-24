"use client";

import Link from "next/link";
import {
    Eye,
    FileText,
    Printer,
} from "lucide-react";
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
            <div className="divide-y divide-[var(--hms-soft-border)]">
                {Array.from({ length: 5 }).map((_, rowIndex) => (
                    <div
                        key={rowIndex}
                        className="grid gap-4 px-6 py-4 md:grid-cols-6"
                    >
                        {Array.from({ length: 6 }).map((__, cellIndex) => (
                            <div
                                key={cellIndex}
                                className="h-5 animate-pulse rounded-lg bg-slate-100"
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
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <FileText aria-hidden="true" className="h-6 w-6" strokeWidth={1.8} />
                    </div>

                    <p className="mt-4 text-sm font-bold text-[var(--hms-text)]">
                        Aucune facture pour ce client.
                    </p>

                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                        Les factures générées pour ce client apparaîtront ici.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-[var(--hms-soft-border)]">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Facture
                        </th>

                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Séjour
                        </th>

                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Paiement
                        </th>

                        <th className="px-6 py-4 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Montant TTC
                        </th>

                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Statut
                        </th>

                        <th className="px-6 py-4 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Actions
                        </th>
                    </tr>
                </thead>

                <tbody className="divide-y divide-[var(--hms-soft-border)] bg-white">
                    {invoices.map((invoice) => (
                        <tr
                            key={invoice.id}
                            className="transition-colors hover:bg-slate-50"
                        >
                            <td className="whitespace-nowrap px-6 py-4">
                                <Link
                                    href={`/invoices/${invoice.id}`}
                                        className="cursor-pointer text-sm font-bold text-[var(--hms-text)] transition-colors hover:text-[var(--hms-primary)]"
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
                                        className="inline-flex h-10 w-10 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        aria-label={`Voir la facture ${invoice.invoiceNumber}`}
                                        title="Voir"
                                    >
                                        <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>

                                    {canPrintInvoice(invoice) && (
                                        <Link
                                            href={`/invoices/${invoice.id}/print`}
                                            className="inline-flex h-10 w-10 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            aria-label={`Imprimer la facture ${invoice.invoiceNumber}`}
                                            title="Imprimer"
                                        >
                                            <Printer aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
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

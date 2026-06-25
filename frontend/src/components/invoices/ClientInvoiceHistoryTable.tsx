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
                        className="grid gap-3 px-4 py-4 md:grid-cols-6"
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
        <div className="overflow-x-auto xl:overflow-visible">
            <table className="w-full table-fixed border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="w-[18%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Facture
                        </th>

                        <th className="w-[25%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Séjour
                        </th>

                        <th className="w-[18%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Paiement
                        </th>

                        <th className="w-[15%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Montant TTC
                        </th>

                        <th className="w-[13%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Statut
                        </th>

                        <th className="w-[11%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Actions
                        </th>
                    </tr>
                </thead>

                <tbody className="bg-white">
                    {invoices.map((invoice) => (
                        <tr
                            key={invoice.id}
                            className="transition-colors hover:bg-slate-50"
                        >
                            <td className="border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <Link
                                    href={`/invoices/${invoice.id}`}
                                    className="cursor-pointer break-words text-sm font-bold text-[var(--hms-text)] transition-colors hover:text-[var(--hms-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                >
                                    {invoice.invoiceNumber}
                                </Link>

                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                    Réservation #{invoice.reservationId}
                                </p>

                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                    Créée le{" "}
                                    <InvoiceDate
                                        value={invoice.createdAt}
                                        className="text-xs text-[var(--hms-text-muted)]"
                                    />
                                </p>
                            </td>

                            <td className="border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm font-semibold text-[var(--hms-text)]">
                                    {formatInvoiceRoom(invoice)}
                                </p>

                                <p className="mt-1 text-xs leading-5 text-[var(--hms-text-muted)]">
                                    {formatInvoicePeriod(invoice)}
                                </p>

                                <p className="mt-1 text-xs leading-5 text-[var(--hms-text-muted)]">
                                    {invoice.nights} nuit(s) ×{" "}
                                    <InvoiceAmount
                                        amount={invoice.pricePerNight}
                                        variant="muted"
                                        className="text-xs"
                                    />
                                </p>
                            </td>

                            <td className="border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm text-[var(--hms-text)]">
                                    {getPaymentMethodDisplayLabel(
                                        invoice.paymentMethod
                                    )}
                                </p>

                                <p className="mt-1 break-words text-xs text-[var(--hms-text-muted)]">
                                    Réf. {invoice.paymentReference ?? "—"}
                                </p>

                                {invoice.paidAt && (
                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        Payée le{" "}
                                        <InvoiceDate
                                            value={invoice.paidAt}
                                            className="text-xs text-[var(--hms-text-muted)]"
                                        />
                                    </p>
                                )}
                            </td>

                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right align-top">
                                <InvoiceAmount
                                    amount={invoice.totalAmount}
                                    variant="strong"
                                    className="text-sm"
                                />

                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                    HT{" "}
                                    <InvoiceAmount
                                        amount={invoice.subtotalAmount}
                                        variant="muted"
                                        className="text-xs"
                                    />
                                </p>
                            </td>

                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center align-top">
                                <InvoiceStatusBadge status={invoice.status} />
                            </td>

                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right align-top">
                                <div className="flex items-center justify-end gap-1.5">
                                    <Link
                                        href={`/invoices/${invoice.id}`}
                                        className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        aria-label={`Voir la facture ${invoice.invoiceNumber}`}
                                        title="Voir"
                                    >
                                        <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>

                                    {canPrintInvoice(invoice) && (
                                        <Link
                                            href={`/invoices/${invoice.id}/print`}
                                            className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
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

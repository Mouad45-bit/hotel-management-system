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
            <div className="divide-y divide-[var(--hms-soft-border)]">
                {Array.from({ length: 5 }).map((_, index) => (
                    <div
                        key={index}
                        className="grid gap-3 px-4 py-4 md:grid-cols-7"
                    >
                        {Array.from({ length: 7 }).map((__, cellIndex) => (
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

                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">
                        {emptyMessage}
                    </p>

                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                        Essayez de modifier les filtres ou de générer une nouvelle
                        facture.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-visible">
            <table className="w-full table-auto border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Facture
                        </th>

                        <th className="border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Client
                        </th>

                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Séjour / chambre
                        </th>

                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Montant TTC
                        </th>

                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Statut
                        </th>

                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Paiement
                        </th>

                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
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
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <div>
                                    <p className="text-sm font-bold text-[var(--hms-text)]">
                                        {invoice.invoiceNumber}
                                    </p>

                                    <p className="mt-1 whitespace-nowrap text-xs text-[var(--hms-text-muted)]">
                                        Créée le{" "}
                                        <InvoiceDate
                                            value={invoice.createdAt}
                                            withTime
                                            className="text-xs text-zinc-500"
                                        />
                                    </p>
                                </div>
                            </td>

                            <td className="border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <div>
                                    <p className="text-sm font-semibold text-[var(--hms-text)]">
                                        {invoice.clientFullName}
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        Client #{invoice.clientId}
                                    </p>
                                </div>
                            </td>

                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <div>
                                    <p className="text-sm font-semibold text-[var(--hms-text)]">
                                        {formatInvoiceRoom(invoice)}
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        Réservation #{invoice.reservationId}
                                    </p>

                                    <p className="mt-1 whitespace-nowrap text-xs text-[var(--hms-text-muted)]">
                                        {formatInvoicePeriod(invoice)}
                                    </p>
                                </div>
                            </td>

                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
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

                                </div>
                            </td>

                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center align-top">
                                <InvoiceStatusBadge status={invoice.status} />
                            </td>

                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm text-[var(--hms-text)]">
                                    {getPaymentMethodDisplayLabel(invoice.paymentMethod)}
                                </p>

                                <p className="mt-1 whitespace-nowrap text-xs text-[var(--hms-text-muted)]">
                                    Réf. {invoice.paymentReference ?? "—"}
                                </p>
                            </td>

                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right align-top">
                                <div className="flex justify-end gap-1.5">
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

                                    <Link
                                        href={`/invoices/${invoice.id}`}
                                        className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        aria-label={`Voir la facture ${invoice.invoiceNumber}`}
                                        title="Voir"
                                    >
                                        <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

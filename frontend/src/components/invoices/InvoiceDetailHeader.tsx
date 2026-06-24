"use client";

import Link from "next/link";
import {
    ArrowLeft,
    Printer,
} from "lucide-react";
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
        <section className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
            <div className="min-w-0">
                <Link
                    href="/invoices"
                    className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    Retour aux factures
                </Link>

                <p className="mt-6 text-xs font-bold uppercase tracking-[0.18em] text-[var(--hms-text-muted)]">
                    {invoice.invoiceNumber}
                </p>

                <div className="mt-3 flex flex-wrap items-center gap-3">
                    <h2 className="text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                        Détail de la facture
                    </h2>

                    <InvoiceStatusBadge status={invoice.status} />
                </div>

                <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                    Facture de {invoice.clientFullName} pour la réservation #{invoice.reservationId}, {formatInvoiceRoom(invoice)}.
                </p>

                <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-2 text-sm text-[var(--hms-text-muted)]">
                    <span>
                        Créée le{" "}
                        <InvoiceDate
                            value={invoice.createdAt}
                            withTime
                            className="text-sm text-[var(--hms-text-muted)]"
                        />
                    </span>

                    <span className="hidden text-[var(--hms-border)] sm:inline">•</span>

                    <span>{formatInvoicePeriod(invoice)}</span>
                </div>
            </div>

            <div className="flex shrink-0 flex-col items-start gap-4 lg:items-end">
                <div className="text-left lg:text-right">
                    <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Montant TTC
                    </p>

                    <InvoiceAmount
                        amount={invoice.totalAmount}
                        variant="strong"
                        className="mt-2 block text-4xl tracking-tight"
                    />
                </div>

                {canPrintInvoice(invoice) && (
                    <Link
                        href={`/invoices/${invoice.id}/print`}
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        <Printer aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        Imprimer
                    </Link>
                )}
            </div>
        </section>
    );
}

"use client";

import Link from "next/link";
import {
    ArrowLeft,
    Printer,
} from "lucide-react";
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
        <HmsCard className="p-7 lg:p-8">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
                <div>
                    <Link
                        href="/invoices"
                        className="inline-flex h-11 w-11 cursor-pointer items-center justify-center rounded-full border border-[var(--hms-border)] bg-white text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                        aria-label="Retour aux factures"
                        title="Retour aux factures"
                    >
                        <ArrowLeft aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </Link>

                    <p className="mt-8 text-xs font-bold uppercase tracking-[0.24em] text-[var(--hms-primary)]">
                        {invoice.invoiceNumber}
                    </p>

                    <div className="mt-4 flex flex-wrap items-center gap-3">
                        <h2 className="text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                            {invoice.invoiceNumber}
                        </h2>

                        <InvoiceStatusBadge status={invoice.status} />
                    </div>

                    <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                        Facture liée à la réservation #{invoice.reservationId}, pour{" "}
                        {invoice.clientFullName}, {formatInvoiceRoom(invoice)}.
                    </p>

                    <div className="mt-5 flex flex-wrap gap-3 text-sm text-[var(--hms-text-muted)]">
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

                <div className="flex flex-col items-start gap-3 lg:items-end">
                    <div className="text-left lg:text-right">
                        <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Montant TTC
                        </p>

                        <InvoiceAmount
                            amount={invoice.totalAmount}
                            variant="strong"
                            className="mt-2 block text-4xl"
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
            </div>
        </HmsCard>
    );
}

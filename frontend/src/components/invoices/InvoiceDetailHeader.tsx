"use client";

import Link from "next/link";
import { Printer } from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import { InvoiceStatusBadge } from "@/components/invoices/InvoiceStatusBadge";
import { PageHeader } from "@/components/layout/PageHeader";
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
        <div className="space-y-6">
            <PageHeader
                backHref="/invoices"
                eyebrow={invoice.invoiceNumber}
                title="Détail de la facture"
                description={`Facture de ${invoice.clientFullName} pour la réservation #${invoice.reservationId}, ${formatInvoiceRoom(invoice)}.`}
                actions={
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
                            <Link href={`/invoices/${invoice.id}/print`}>
                                <HmsButton variant="secondary">
                                    <Printer aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    Imprimer
                                </HmsButton>
                            </Link>
                        )}
                    </div>
                }
            />

            <div className="flex flex-wrap items-center gap-3">
                <InvoiceStatusBadge status={invoice.status} />
                <span className="text-sm text-[var(--hms-text-muted)]">
                    Créée le{" "}
                    <InvoiceDate
                        value={invoice.createdAt}
                        withTime
                        className="text-sm text-[var(--hms-text-muted)]"
                    />
                </span>
                <span className="hidden text-[var(--hms-border)] sm:inline">•</span>
                <span className="text-sm text-[var(--hms-text-muted)]">{formatInvoicePeriod(invoice)}</span>
            </div>
        </div>
    );
}

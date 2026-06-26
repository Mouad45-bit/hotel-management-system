"use client";

import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { getInvoiceLineTypeDisplayLabel } from "@/lib/invoiceHelpers";
import type { Invoice } from "@/types/invoice";

interface InvoiceLinesTableProps {
    invoice: Invoice;
}

export function InvoiceLinesTable({ invoice }: InvoiceLinesTableProps) {
    return (
        <HmsCard className="overflow-hidden p-0">
            <div className="border-b border-[var(--hms-soft-border)] px-6 py-5">
                <h3 className="text-lg font-bold text-[var(--hms-text)]">
                    Lignes de facture
                </h3>

                <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                    Détail des prestations facturées.
                </p>
            </div>

            <div className="overflow-x-auto">
                <table className="w-full min-w-[680px] table-fixed border-collapse xl:min-w-0">
                    <thead className="bg-slate-50">
                        <tr>
                            <th className="w-[18%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Type
                            </th>

                            <th className="w-[34%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Description
                            </th>

                            <th className="w-[12%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Quantité
                            </th>

                            <th className="w-[18%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Prix unitaire
                            </th>

                            <th className="w-[18%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Total ligne
                            </th>
                        </tr>
                    </thead>

                    <tbody className="bg-white">
                        {invoice.lines.map((line) => (
                            <tr key={line.id}>
                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-4 align-top text-sm font-semibold text-[var(--hms-text)]">
                                    {getInvoiceLineTypeDisplayLabel(line.type)}
                                </td>

                                <td className="border-b border-[var(--hms-soft-border)] px-3 py-4 align-top text-sm leading-6 text-[var(--hms-text-muted)]">
                                    {line.description}
                                </td>

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-4 text-right align-top text-sm text-[var(--hms-text-muted)]">
                                    {line.quantity}
                                </td>

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-4 text-right align-top">
                                    <InvoiceAmount
                                        amount={line.unitPrice}
                                        variant="muted"
                                        className="text-sm"
                                    />
                                </td>

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-4 text-right align-top">
                                    <InvoiceAmount
                                        amount={line.lineTotal}
                                        variant="strong"
                                        className="text-sm"
                                    />
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div className="bg-slate-50 px-6 py-5">
                <div className="ml-auto w-full max-w-sm space-y-3">
                    <div className="flex items-center justify-between gap-4 text-sm">
                        <span className="text-[var(--hms-text-muted)]">Montant HT</span>
                        <InvoiceAmount
                            amount={invoice.subtotalAmount}
                            variant="default"
                            className="text-sm"
                        />
                    </div>

                    <div className="flex items-center justify-between gap-4 text-sm">
                        <span className="text-[var(--hms-text-muted)]">
                            Taxe ({invoice.taxRate}%)
                        </span>

                        <InvoiceAmount
                            amount={invoice.taxAmount}
                            variant="default"
                            className="text-sm"
                        />
                    </div>

                    <div className="flex items-center justify-between gap-4 border-t border-[var(--hms-border)] pt-3">
                        <span className="text-sm font-semibold text-[var(--hms-text)]">
                            Total TTC
                        </span>

                        <InvoiceAmount
                            amount={invoice.totalAmount}
                            variant="strong"
                            className="text-xl tracking-tight"
                        />
                    </div>
                </div>
            </div>
        </HmsCard>
    );
}

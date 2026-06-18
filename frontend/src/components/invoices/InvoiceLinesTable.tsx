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
        <HmsCard className="p-0">
            <div className="border-b border-zinc-200 px-6 py-4">
                <h3 className="text-sm font-semibold text-zinc-950">
                    Lignes de facture
                </h3>

                <p className="mt-1 text-sm text-zinc-500">
                    Détail des prestations facturées.
                </p>
            </div>

            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-zinc-200">
                    <thead className="bg-zinc-50">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Type
                            </th>

                            <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Description
                            </th>

                            <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Quantité
                            </th>

                            <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Prix unitaire
                            </th>

                            <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Total ligne
                            </th>
                        </tr>
                    </thead>

                    <tbody className="divide-y divide-zinc-100 bg-white">
                        {invoice.lines.map((line) => (
                            <tr key={line.id}>
                                <td className="whitespace-nowrap px-6 py-4 text-sm font-medium text-zinc-900">
                                    {getInvoiceLineTypeDisplayLabel(line.type)}
                                </td>

                                <td className="min-w-72 px-6 py-4 text-sm text-zinc-600">
                                    {line.description}
                                </td>

                                <td className="whitespace-nowrap px-6 py-4 text-right text-sm text-zinc-600">
                                    {line.quantity}
                                </td>

                                <td className="whitespace-nowrap px-6 py-4 text-right">
                                    <InvoiceAmount
                                        amount={line.unitPrice}
                                        variant="muted"
                                        className="text-sm"
                                    />
                                </td>

                                <td className="whitespace-nowrap px-6 py-4 text-right">
                                    <InvoiceAmount
                                        amount={line.lineTotal}
                                        variant="default"
                                        className="text-sm"
                                    />
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div className="border-t border-zinc-200 bg-zinc-50 px-6 py-4">
                <div className="ml-auto w-full max-w-sm space-y-2">
                    <div className="flex items-center justify-between text-sm">
                        <span className="text-zinc-500">Montant HT</span>
                        <InvoiceAmount
                            amount={invoice.subtotalAmount}
                            variant="default"
                            className="text-sm"
                        />
                    </div>

                    <div className="flex items-center justify-between text-sm">
                        <span className="text-zinc-500">
                            Taxe ({invoice.taxRate}%)
                        </span>

                        <InvoiceAmount
                            amount={invoice.taxAmount}
                            variant="default"
                            className="text-sm"
                        />
                    </div>

                    <div className="flex items-center justify-between border-t border-zinc-200 pt-2">
                        <span className="text-sm font-semibold text-zinc-950">
                            Total TTC
                        </span>

                        <InvoiceAmount
                            amount={invoice.totalAmount}
                            variant="strong"
                            className="text-lg"
                        />
                    </div>
                </div>
            </div>
        </HmsCard>
    );
}

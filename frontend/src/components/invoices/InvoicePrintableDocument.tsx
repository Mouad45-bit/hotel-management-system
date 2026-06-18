import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import { InvoiceStatusBadge } from "@/components/invoices/InvoiceStatusBadge";
import {
    formatInvoicePeriod,
    formatInvoiceRoom,
    getInvoiceLineTypeDisplayLabel,
    getPaymentMethodDisplayLabel,
} from "@/lib/invoiceHelpers";
import type { Invoice } from "@/types/invoice";

interface InvoicePrintableDocumentProps {
    invoice: Invoice;
}

export function InvoicePrintableDocument({
    invoice,
}: InvoicePrintableDocumentProps) {
    const issueDate = invoice.issuedAt ?? invoice.createdAt;
    const paymentLabel = getPaymentMethodDisplayLabel(invoice.paymentMethod);

    return (
        <article className="hms-print-document min-h-[297mm] rounded-2xl bg-white p-10 text-zinc-950 shadow-xl ring-1 ring-zinc-200 print:min-h-0 print:rounded-none print:p-0 print:shadow-none print:ring-0">
            <header className="flex flex-col gap-8 border-b border-zinc-200 pb-8 sm:flex-row sm:items-start sm:justify-between">
                <div>
                    <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-stone-900 text-xl font-bold text-white print:bg-stone-900">
                        HMS
                    </div>

                    <div className="mt-4">
                        <p className="text-lg font-semibold tracking-tight">
                            Hotel Management System
                        </p>

                        <p className="mt-1 text-sm leading-6 text-zinc-500">
                            Gestion hôtelière · Facturation · Paiements
                        </p>
                    </div>

                    <div className="mt-5 text-sm leading-6 text-zinc-500">
                        <p>Adresse : Casablanca, Maroc</p>
                        <p>Téléphone : +212 5 00 00 00 00</p>
                        <p>Email : billing@hms.local</p>
                    </div>
                </div>

                <div className="text-left sm:text-right">
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">
                        Facture
                    </p>

                    <h1 className="mt-2 text-3xl font-semibold tracking-tight">
                        {invoice.invoiceNumber}
                    </h1>

                    <div className="mt-4 flex justify-start sm:justify-end">
                        <InvoiceStatusBadge status={invoice.status} />
                    </div>

                    <div className="mt-5 space-y-1 text-sm text-zinc-500">
                        <p>
                            Date d’émission :{" "}
                            <InvoiceDate
                                value={issueDate}
                                withTime
                                className="text-sm text-zinc-600"
                            />
                        </p>

                        <p>
                            Créée le :{" "}
                            <InvoiceDate
                                value={invoice.createdAt}
                                withTime
                                className="text-sm text-zinc-600"
                            />
                        </p>
                    </div>
                </div>
            </header>

            <section className="grid gap-6 border-b border-zinc-200 py-8 md:grid-cols-2">
                <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                        Facturé à
                    </p>

                    <p className="mt-3 text-base font-semibold">
                        {invoice.clientFullName}
                    </p>

                    <div className="mt-2 text-sm leading-6 text-zinc-500">
                        <p>Client #{invoice.clientId}</p>
                        <p>Réservation #{invoice.reservationId}</p>
                    </div>
                </div>

                <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                        Séjour
                    </p>

                    <p className="mt-3 text-base font-semibold">
                        {formatInvoiceRoom(invoice)}
                    </p>

                    <div className="mt-2 text-sm leading-6 text-zinc-500">
                        <p>{formatInvoicePeriod(invoice)}</p>

                        <p>
                            Check-in :{" "}
                            <InvoiceDate
                                value={invoice.checkInDate}
                                className="text-sm text-zinc-500"
                            />
                        </p>

                        <p>
                            Check-out :{" "}
                            <InvoiceDate
                                value={invoice.checkOutDate}
                                className="text-sm text-zinc-500"
                            />
                        </p>

                        <p>{invoice.nights} nuit(s)</p>
                    </div>
                </div>
            </section>

            <section className="py-8">
                <table className="w-full border-collapse text-sm">
                    <thead>
                        <tr className="border-b border-zinc-200">
                            <th className="py-3 pr-4 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Type
                            </th>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Description
                            </th>

                            <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Qté
                            </th>

                            <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Prix unitaire
                            </th>

                            <th className="py-3 pl-4 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Total
                            </th>
                        </tr>
                    </thead>

                    <tbody>
                        {invoice.lines.map((line) => (
                            <tr
                                key={line.id}
                                className="border-b border-zinc-100"
                            >
                                <td className="py-4 pr-4 align-top font-medium">
                                    {getInvoiceLineTypeDisplayLabel(line.type)}
                                </td>

                                <td className="px-4 py-4 align-top text-zinc-600">
                                    {line.description}
                                </td>

                                <td className="px-4 py-4 text-right align-top text-zinc-600">
                                    {line.quantity}
                                </td>

                                <td className="px-4 py-4 text-right align-top">
                                    <InvoiceAmount
                                        amount={line.unitPrice}
                                        variant="muted"
                                        className="text-sm"
                                    />
                                </td>

                                <td className="py-4 pl-4 text-right align-top">
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
            </section>

            <section className="grid gap-8 border-t border-zinc-200 pt-8 md:grid-cols-[1fr_320px]">
                <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                        Paiement
                    </p>

                    <div className="mt-3 text-sm leading-6 text-zinc-600">
                        <p>Méthode : {paymentLabel}</p>
                        <p>Référence : {invoice.paymentReference ?? "—"}</p>

                        {invoice.paidAt && (
                            <p>
                                Date de paiement :{" "}
                                <InvoiceDate
                                    value={invoice.paidAt}
                                    withTime
                                    className="text-sm text-zinc-600"
                                />
                            </p>
                        )}
                    </div>

                    {invoice.notes && (
                        <div className="mt-6">
                            <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                Notes
                            </p>

                            <p className="mt-2 text-sm leading-6 text-zinc-600">
                                {invoice.notes}
                            </p>
                        </div>
                    )}

                    {invoice.cancellationReason && (
                        <div className="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                            <p className="font-semibold">Motif d’annulation</p>
                            <p className="mt-1">{invoice.cancellationReason}</p>
                        </div>
                    )}

                    {invoice.refundReason && (
                        <div className="mt-6 rounded-xl border border-purple-200 bg-purple-50 p-4 text-sm text-purple-700">
                            <p className="font-semibold">
                                Motif de remboursement
                            </p>
                            <p className="mt-1">{invoice.refundReason}</p>
                        </div>
                    )}
                </div>

                <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-5">
                    <div className="space-y-3">
                        <div className="flex items-center justify-between gap-4 text-sm">
                            <span className="text-zinc-500">Montant HT</span>

                            <InvoiceAmount
                                amount={invoice.subtotalAmount}
                                variant="default"
                                className="text-sm"
                            />
                        </div>

                        <div className="flex items-center justify-between gap-4 text-sm">
                            <span className="text-zinc-500">
                                Taxe ({invoice.taxRate}%)
                            </span>

                            <InvoiceAmount
                                amount={invoice.taxAmount}
                                variant="default"
                                className="text-sm"
                            />
                        </div>

                        <div className="flex items-center justify-between gap-4 border-t border-zinc-200 pt-4">
                            <span className="text-sm font-semibold">
                                Total TTC
                            </span>

                            <InvoiceAmount
                                amount={invoice.totalAmount}
                                variant="strong"
                                className="text-xl"
                            />
                        </div>
                    </div>
                </div>
            </section>

            <footer className="mt-12 grid gap-8 border-t border-zinc-200 pt-8 md:grid-cols-2">
                <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                        Conditions
                    </p>

                    <p className="mt-2 text-sm leading-6 text-zinc-500">
                        Cette facture est générée par HMS à partir des données de
                        réservation figées au moment de la facturation.
                    </p>
                </div>

                <div className="text-left md:text-right">
                    <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                        Signature
                    </p>

                    <div className="mt-10 border-t border-zinc-300 pt-2 text-sm text-zinc-500">
                        Responsable réception / facturation
                    </div>
                </div>
            </footer>
        </article>
    );
}

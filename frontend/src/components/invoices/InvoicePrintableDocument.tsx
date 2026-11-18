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
        <article className="hms-print-document min-h-[297mm] w-[210mm] max-w-full rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-8 text-[var(--hms-text)] shadow-[0_18px_55px_rgba(13,9,7,0.06)] sm:p-10 print:min-h-0 print:w-full print:max-w-none print:rounded-none print:border-0 print:p-0 print:shadow-none">
            <header className="hms-print-avoid-break grid gap-8 border-b border-[var(--hms-soft-border)] pb-8 sm:grid-cols-[1fr_auto] sm:items-start">
                <div className="max-w-md">
                    <div className="flex items-start gap-4">
                        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-xl font-extrabold tracking-tight text-white print:bg-[var(--hms-primary)]">
                            HMS
                        </div>

                        <div>
                            <p className="text-lg font-bold tracking-tight text-[var(--hms-text)]">
                                Hotel Management System
                            </p>

                            <p className="mt-1 text-sm leading-6 text-[var(--hms-text-muted)]">
                                Gestion hôtelière · Facturation · Paiements
                            </p>
                        </div>
                    </div>

                    <div className="mt-6 space-y-1 text-sm leading-6 text-[var(--hms-text-muted)]">
                        <p>Adresse : Casablanca, Maroc</p>
                        <p>Téléphone : +212 5 00 00 00 00</p>
                        <p>Email : billing@hms.local</p>
                    </div>
                </div>

                <div className="sm:min-w-72 sm:text-right">
                    <p className="text-xs font-bold uppercase tracking-[0.18em] text-[var(--hms-text-muted)]">
                        Facture
                    </p>

                    <h1 className="mt-3 text-3xl font-extrabold tracking-tight text-[var(--hms-text)]">
                        {invoice.invoiceNumber}
                    </h1>

                    <div className="mt-4 flex justify-start sm:justify-end">
                        <InvoiceStatusBadge status={invoice.status} />
                    </div>

                    <dl className="mt-6 space-y-2 text-sm">
                        <div className="flex justify-between gap-4 sm:justify-end">
                            <dt className="text-[var(--hms-text-muted)]">
                                Date d’émission
                            </dt>
                            <dd className="font-medium text-[var(--hms-text)]">
                                <InvoiceDate
                                    value={issueDate}
                                    withTime
                                    className="text-sm text-[var(--hms-text)]"
                                />
                            </dd>
                        </div>

                        <div className="flex justify-between gap-4 sm:justify-end">
                            <dt className="text-[var(--hms-text-muted)]">
                                Créée le
                            </dt>
                            <dd className="font-medium text-[var(--hms-text)]">
                                <InvoiceDate
                                    value={invoice.createdAt}
                                    withTime
                                    className="text-sm text-[var(--hms-text)]"
                                />
                            </dd>
                        </div>
                    </dl>
                </div>
            </header>

            <section className="hms-print-avoid-break grid gap-6 border-b border-[var(--hms-soft-border)] py-8 md:grid-cols-2">
                <div>
                    <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Facturé à
                    </p>

                    <p className="mt-3 text-base font-bold text-[var(--hms-text)]">
                        {invoice.clientFullName}
                    </p>

                    <div className="mt-3 space-y-1 text-sm leading-6 text-[var(--hms-text-muted)]">
                        <p>Client #{invoice.clientId}</p>
                        <p>Réservation #{invoice.reservationId}</p>
                    </div>
                </div>

                <div>
                    <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Séjour
                    </p>

                    <p className="mt-3 text-base font-bold text-[var(--hms-text)]">
                        {formatInvoiceRoom(invoice)}
                    </p>

                    <div className="mt-3 space-y-1 text-sm leading-6 text-[var(--hms-text-muted)]">
                        <p className="whitespace-nowrap">{formatInvoicePeriod(invoice)}</p>

                        <p>
                            Check-in :{" "}
                            <InvoiceDate
                                value={invoice.checkInDate}
                                className="text-sm text-[var(--hms-text-muted)]"
                            />
                        </p>

                        <p>
                            Check-out :{" "}
                            <InvoiceDate
                                value={invoice.checkOutDate}
                                className="text-sm text-[var(--hms-text-muted)]"
                            />
                        </p>

                        <p>{invoice.nights} nuit(s)</p>
                    </div>
                </div>
            </section>

            <section className="py-8">
                <table className="w-full table-fixed border-collapse text-sm">
                    <thead className="bg-slate-50">
                        <tr>
                            <th className="w-[18%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Type
                            </th>

                            <th className="w-[34%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Description
                            </th>

                            <th className="w-[12%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Quantité
                            </th>

                            <th className="w-[18%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Prix unitaire
                            </th>

                            <th className="w-[18%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Total
                            </th>
                        </tr>
                    </thead>

                    <tbody className="bg-white">
                        {invoice.lines.map((line) => (
                            <tr
                                key={line.id}
                                className="hms-print-line border-b border-[var(--hms-soft-border)]"
                            >
                                <td className="px-3 py-4 align-top text-sm font-semibold text-[var(--hms-text)]">
                                    {getInvoiceLineTypeDisplayLabel(line.type)}
                                </td>

                                <td className="px-3 py-4 align-top text-sm leading-6 text-[var(--hms-text-muted)]">
                                    {line.description}
                                </td>

                                <td className="px-3 py-4 text-center align-top text-sm text-[var(--hms-text-muted)]">
                                    {line.quantity}
                                </td>

                                <td className="whitespace-nowrap px-3 py-4 text-right align-top">
                                    <InvoiceAmount
                                        amount={line.unitPrice}
                                        variant="muted"
                                        className="text-sm"
                                    />
                                </td>

                                <td className="whitespace-nowrap px-3 py-4 text-right align-top">
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

            <section className="hms-print-avoid-break grid gap-8 border-t border-[var(--hms-soft-border)] pt-8 md:grid-cols-[1fr_320px]">
                <div>
                    <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Paiement
                    </p>

                    <div className="mt-3 space-y-1 text-sm leading-6 text-[var(--hms-text-muted)]">
                        <p>Méthode : {paymentLabel}</p>
                        <p>Référence : {invoice.paymentReference ?? "—"}</p>

                        {invoice.paidAt && (
                            <p>
                                Date de paiement :{" "}
                                <InvoiceDate
                                    value={invoice.paidAt}
                                    withTime
                                    className="text-sm text-[var(--hms-text-muted)]"
                                />
                            </p>
                        )}
                    </div>

                    {invoice.notes && (
                        <div className="mt-6">
                            <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                Notes
                            </p>

                            <p className="mt-2 text-sm leading-6 text-[var(--hms-text-muted)]">
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

                <div className="hms-print-total rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-5">
                    <div className="space-y-3">
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

                        <div className="flex items-center justify-between gap-4 border-t border-[var(--hms-border)] pt-4">
                            <span className="text-sm font-bold text-[var(--hms-text)]">
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

            <footer className="hms-print-footer mt-12 grid gap-8 border-t border-[var(--hms-soft-border)] pt-8 md:grid-cols-2">
                <div>
                    <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Conditions
                    </p>

                    <p className="mt-2 text-sm leading-6 text-[var(--hms-text-muted)]">
                        Cette facture est générée par HMS à partir des données de
                        réservation figées au moment de la facturation.
                    </p>
                </div>

                <div className="text-left md:text-right">
                    <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                        Signature
                    </p>

                    <div className="mt-10 border-t border-[var(--hms-border)] pt-2 text-sm text-[var(--hms-text-muted)]">
                        Responsable réception / facturation
                    </div>
                </div>
            </footer>
        </article>
    );
}

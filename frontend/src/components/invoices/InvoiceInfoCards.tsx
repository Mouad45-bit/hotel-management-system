"use client";

import {
    BedDouble,
    CalendarDays,
    CreditCard,
    UsersRound,
} from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import {
    formatInvoiceRoom,
    getPaymentMethodDisplayLabel,
} from "@/lib/invoiceHelpers";
import type { Invoice } from "@/types/invoice";

interface InvoiceInfoCardsProps {
    invoice: Invoice;
}

export function InvoiceInfoCards({ invoice }: InvoiceInfoCardsProps) {
    return (
        <div className="grid gap-5 md:grid-cols-2">
            <HmsCard className="p-5">
                <div className="flex items-start gap-3">
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <UsersRound aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div className="min-w-0">
                        <p className="text-sm font-semibold text-[var(--hms-text-muted)]">
                            Client
                        </p>

                        <p className="mt-2 text-base font-bold text-[var(--hms-text)]">
                            {invoice.clientFullName}
                        </p>

                        <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                            Identifiant client #{invoice.clientId}
                        </p>
                    </div>
                </div>
            </HmsCard>

            <HmsCard className="p-5">
                <div className="flex items-start gap-3">
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <BedDouble aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div className="min-w-0">
                        <p className="text-sm font-semibold text-[var(--hms-text-muted)]">
                            Chambre
                        </p>

                        <p className="mt-2 text-base font-bold text-[var(--hms-text)]">
                            {formatInvoiceRoom(invoice)}
                        </p>

                        <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                            Identifiant chambre #{invoice.roomId}
                        </p>
                    </div>
                </div>
            </HmsCard>

            <HmsCard className="p-5">
                <div className="flex items-start gap-3">
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <CalendarDays aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div className="min-w-0">
                        <p className="text-sm font-semibold text-[var(--hms-text-muted)]">
                            Séjour
                        </p>

                        <div className="mt-2 space-y-1 text-sm text-[var(--hms-text)]">
                            <p>
                                Arrivée :{" "}
                                <InvoiceDate
                                    value={invoice.checkInDate}
                                    className="text-sm text-[var(--hms-text)]"
                                />
                            </p>

                            <p>
                                Départ :{" "}
                                <InvoiceDate
                                    value={invoice.checkOutDate}
                                    className="text-sm text-[var(--hms-text)]"
                                />
                            </p>

                            <p className="font-semibold">{invoice.nights} nuit(s)</p>
                        </div>
                    </div>
                </div>
            </HmsCard>

            <HmsCard className="p-5">
                <div className="flex items-start gap-3">
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <CreditCard aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div className="min-w-0">
                        <p className="text-sm font-semibold text-[var(--hms-text-muted)]">
                            Paiement
                        </p>

                        <p className="mt-2 text-base font-bold text-[var(--hms-text)]">
                            {getPaymentMethodDisplayLabel(invoice.paymentMethod)}
                        </p>

                        <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                            Référence : {invoice.paymentReference ?? "—"}
                        </p>

                        {invoice.paidAt && (
                            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                                Payée le{" "}
                                <InvoiceDate
                                    value={invoice.paidAt}
                                    withTime
                                    className="text-sm text-[var(--hms-text-muted)]"
                                />
                            </p>
                        )}
                    </div>
                </div>
            </HmsCard>

            {(invoice.notes ||
                invoice.cancellationReason ||
                invoice.refundReason) && (
                <HmsCard className="p-6 md:col-span-2">
                    <h3 className="text-lg font-bold text-[var(--hms-text)]">
                        Notes et motifs
                    </h3>

                    <div className="mt-4 space-y-3">
                        {invoice.notes && (
                            <div>
                                <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                    Notes
                                </p>

                                <p className="mt-1 text-sm leading-6 text-[var(--hms-text-muted)]">
                                    {invoice.notes}
                                </p>
                            </div>
                        )}

                        {invoice.cancellationReason && (
                            <div>
                                <p className="text-xs font-medium uppercase tracking-wide text-red-500">
                                    Motif d’annulation
                                </p>

                                <p className="mt-1 text-sm text-red-700">
                                    {invoice.cancellationReason}
                                </p>
                            </div>
                        )}

                        {invoice.refundReason && (
                            <div>
                                <p className="text-xs font-medium uppercase tracking-wide text-purple-500">
                                    Motif de remboursement
                                </p>

                                <p className="mt-1 text-sm text-purple-700">
                                    {invoice.refundReason}
                                </p>
                            </div>
                        )}
                    </div>
                </HmsCard>
            )}

            <HmsCard className="p-6 md:col-span-2">
                <h3 className="text-lg font-bold text-[var(--hms-text)]">
                    Snapshot de réservation
                </h3>

                <p className="mt-1 max-w-3xl text-sm leading-6 text-[var(--hms-text-muted)]">
                    La facture conserve les informations financières au moment de
                    sa génération : client, chambre, dates, nombre de nuits, prix
                    par nuit et montants calculés.
                </p>

                <div className="mt-5 grid gap-4 rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm sm:grid-cols-3">
                    <div>
                        <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Réservation
                        </p>
                        <p className="mt-2 font-bold text-[var(--hms-text)]">
                            #{invoice.reservationId}
                        </p>
                    </div>

                    <div>
                        <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Prix figé
                        </p>

                        <InvoiceAmount
                            amount={invoice.pricePerNight}
                            variant="default"
                            className="mt-2 block text-sm"
                        />
                    </div>

                    <div>
                        <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Dernière mise à jour
                        </p>

                        <InvoiceDate
                            value={invoice.updatedAt}
                            withTime
                            className="mt-2 block text-sm text-[var(--hms-text)]"
                        />
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}

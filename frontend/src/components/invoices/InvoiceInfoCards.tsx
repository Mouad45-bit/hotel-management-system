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
        <div className="grid gap-4 lg:grid-cols-2">
            <HmsCard>
                <div className="flex items-start gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-zinc-100 text-zinc-700">
                        <UsersRound aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div>
                        <p className="text-sm font-semibold text-zinc-950">
                            Client
                        </p>

                        <p className="mt-2 text-sm font-medium text-zinc-900">
                            {invoice.clientFullName}
                        </p>

                        <p className="mt-1 text-sm text-zinc-500">
                            Identifiant client #{invoice.clientId}
                        </p>
                    </div>
                </div>
            </HmsCard>

            <HmsCard>
                <div className="flex items-start gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-zinc-100 text-zinc-700">
                        <BedDouble aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div>
                        <p className="text-sm font-semibold text-zinc-950">
                            Chambre
                        </p>

                        <p className="mt-2 text-sm font-medium text-zinc-900">
                            {formatInvoiceRoom(invoice)}
                        </p>

                        <p className="mt-1 text-sm text-zinc-500">
                            Identifiant chambre #{invoice.roomId}
                        </p>
                    </div>
                </div>
            </HmsCard>

            <HmsCard>
                <div className="flex items-start gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-zinc-100 text-zinc-700">
                        <CalendarDays aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div>
                        <p className="text-sm font-semibold text-zinc-950">
                            Séjour
                        </p>

                        <div className="mt-2 space-y-1 text-sm text-zinc-600">
                            <p>
                                Arrivée :{" "}
                                <InvoiceDate
                                    value={invoice.checkInDate}
                                    className="text-sm text-zinc-600"
                                />
                            </p>

                            <p>
                                Départ :{" "}
                                <InvoiceDate
                                    value={invoice.checkOutDate}
                                    className="text-sm text-zinc-600"
                                />
                            </p>

                            <p>{invoice.nights} nuit(s)</p>
                        </div>
                    </div>
                </div>
            </HmsCard>

            <HmsCard>
                <div className="flex items-start gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-zinc-100 text-zinc-700">
                        <CreditCard aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    </div>

                    <div>
                        <p className="text-sm font-semibold text-zinc-950">
                            Paiement
                        </p>

                        <p className="mt-2 text-sm font-medium text-zinc-900">
                            {getPaymentMethodDisplayLabel(invoice.paymentMethod)}
                        </p>

                        <p className="mt-1 text-sm text-zinc-500">
                            Référence : {invoice.paymentReference ?? "—"}
                        </p>

                        {invoice.paidAt && (
                            <p className="mt-1 text-sm text-zinc-500">
                                Payée le{" "}
                                <InvoiceDate
                                    value={invoice.paidAt}
                                    withTime
                                    className="text-sm text-zinc-500"
                                />
                            </p>
                        )}
                    </div>
                </div>
            </HmsCard>

            {(invoice.notes ||
                invoice.cancellationReason ||
                invoice.refundReason) && (
                <HmsCard className="lg:col-span-2">
                    <p className="text-sm font-semibold text-zinc-950">
                        Notes et motifs
                    </p>

                    <div className="mt-4 space-y-3">
                        {invoice.notes && (
                            <div>
                                <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                                    Notes
                                </p>

                                <p className="mt-1 text-sm text-zinc-600">
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

            <HmsCard className="lg:col-span-2">
                <p className="text-sm font-semibold text-zinc-950">
                    Snapshot de réservation
                </p>

                <p className="mt-2 text-sm leading-6 text-zinc-500">
                    La facture conserve les informations financières au moment de
                    sa génération : client, chambre, dates, nombre de nuits, prix
                    par nuit et montants calculés.
                </p>

                <div className="mt-4 grid gap-3 text-sm md:grid-cols-3">
                    <div>
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                            Réservation
                        </p>
                        <p className="mt-1 font-semibold text-zinc-950">
                            #{invoice.reservationId}
                        </p>
                    </div>

                    <div>
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                            Prix figé
                        </p>

                        <InvoiceAmount
                            amount={invoice.pricePerNight}
                            variant="default"
                            className="mt-1 block text-sm"
                        />
                    </div>

                    <div>
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                            Dernière mise à jour
                        </p>

                        <InvoiceDate
                            value={invoice.updatedAt}
                            withTime
                            className="mt-1 block text-sm text-zinc-600"
                        />
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}

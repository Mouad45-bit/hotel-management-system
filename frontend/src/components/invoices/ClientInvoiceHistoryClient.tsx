"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
    ArrowLeftIcon,
    ArrowPathIcon,
    DocumentPlusIcon,
    ExclamationTriangleIcon,
    UserIcon,
} from "@heroicons/react/24/outline";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import {
    ClientInvoiceSummaryCards,
    type ClientInvoiceSummary,
} from "@/components/invoices/ClientInvoiceSummaryCards";
import { ClientInvoiceHistoryTable } from "@/components/invoices/ClientInvoiceHistoryTable";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import { InvoiceStatusBadge } from "@/components/invoices/InvoiceStatusBadge";
import { getInvoicesByClientId } from "@/services/invoiceApi";
import type { Invoice } from "@/types/invoice";

interface ClientInvoiceHistoryClientProps {
    clientId: number;
}

const EMPTY_SUMMARY: ClientInvoiceSummary = {
    totalInvoices: 0,
    paidInvoices: 0,
    issuedInvoices: 0,
    refundedInvoices: 0,
    totalRevenue: 0,
    pendingAmount: 0,
    refundedAmount: 0,
};

function sortInvoicesByCreationDate(invoices: Invoice[]): Invoice[] {
    return [...invoices].sort((first, second) =>
        second.createdAt.localeCompare(first.createdAt)
    );
}

function calculateClientSummary(invoices: Invoice[]): ClientInvoiceSummary {
    return {
        totalInvoices: invoices.length,

        paidInvoices: invoices.filter((invoice) => invoice.status === "PAID")
            .length,

        issuedInvoices: invoices.filter((invoice) => invoice.status === "ISSUED")
            .length,

        refundedInvoices: invoices.filter(
            (invoice) => invoice.status === "REFUNDED"
        ).length,

        totalRevenue: invoices
            .filter((invoice) => invoice.status === "PAID")
            .reduce((sum, invoice) => sum + invoice.totalAmount, 0),

        pendingAmount: invoices
            .filter((invoice) => invoice.status === "ISSUED")
            .reduce((sum, invoice) => sum + invoice.totalAmount, 0),

        refundedAmount: invoices
            .filter((invoice) => invoice.status === "REFUNDED")
            .reduce((sum, invoice) => sum + invoice.totalAmount, 0),
    };
}

export function ClientInvoiceHistoryClient({
    clientId,
}: ClientInvoiceHistoryClientProps) {
    const [invoices, setInvoices] = useState<Invoice[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    const isValidClientId = Number.isFinite(clientId) && clientId > 0;

    const sortedInvoices = useMemo(
        () => sortInvoicesByCreationDate(invoices),
        [invoices]
    );

    const summary = useMemo(
        () =>
            invoices.length > 0
                ? calculateClientSummary(invoices)
                : EMPTY_SUMMARY,
        [invoices]
    );

    const clientName = sortedInvoices[0]?.clientFullName ?? `Client #${clientId}`;
    const latestInvoice = sortedInvoices[0] ?? null;

    async function loadClientInvoices() {
        if (!isValidClientId) {
            setInvoices([]);
            setErrorMessage("Identifiant client invalide.");
            setIsLoading(false);
            return;
        }

        setIsLoading(true);
        setErrorMessage(null);

        try {
            const loadedInvoices = await getInvoicesByClientId(clientId);
            setInvoices(loadedInvoices);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger l’historique des factures client."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        void loadClientInvoices();
    }, [clientId]);

    return (
        <div className="space-y-6">
            <HmsCard>
                <div className="flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between">
                    <div>
                        <Link
                            href="/invoices"
                            className="inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                        >
                            <ArrowLeftIcon className="h-4 w-4" />
                            Retour aux factures
                        </Link>

                        <div className="mt-5 flex items-start gap-3">
                            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-stone-900 text-white">
                                <UserIcon className="h-6 w-6" />
                            </div>

                            <div>
                                <p className="text-sm font-medium text-stone-700">
                                    Historique de facturation
                                </p>

                                <h2 className="mt-1 text-2xl font-semibold tracking-tight text-zinc-950">
                                    {clientName}
                                </h2>

                                <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-500">
                                    Consultation des factures, paiements,
                                    remboursements et montants liés au client #
                                    {clientId}.
                                </p>
                            </div>
                        </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-3">
                        <HmsButton
                            type="button"
                            variant="secondary"
                            onClick={() => void loadClientInvoices()}
                            disabled={isLoading}
                        >
                            <ArrowPathIcon className="mr-2 h-5 w-5" />
                            Actualiser
                        </HmsButton>

                        <Link
                            href="/invoices/create"
                            className="inline-flex items-center justify-center rounded-xl bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800"
                        >
                            <DocumentPlusIcon className="mr-2 h-5 w-5" />
                            Générer facture
                        </Link>
                    </div>
                </div>
            </HmsCard>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />

                    <div>
                        <p className="font-semibold">Erreur de chargement</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <ClientInvoiceSummaryCards summary={summary} />

            <div className="grid gap-6 xl:grid-cols-[1fr_360px]">
                <HmsCard className="p-0">
                    <div className="flex flex-col gap-3 border-b border-zinc-200 px-6 py-4 lg:flex-row lg:items-center lg:justify-between">
                        <div>
                            <h3 className="text-sm font-semibold text-zinc-950">
                                Factures du client
                            </h3>

                            <p className="mt-1 text-sm text-zinc-500">
                                Liste chronologique des factures liées au client.
                            </p>
                        </div>

                        <p className="text-sm text-zinc-500">
                            {summary.totalInvoices} résultat(s)
                        </p>
                    </div>

                    <ClientInvoiceHistoryTable
                        invoices={sortedInvoices}
                        loading={isLoading}
                    />
                </HmsCard>

                <div className="space-y-6">
                    <HmsCard>
                        <h3 className="text-sm font-semibold text-zinc-950">
                            Synthèse client
                        </h3>

                        <p className="mt-1 text-sm text-zinc-500">
                            Vue rapide du comportement de facturation.
                        </p>

                        <div className="mt-5 space-y-4">
                            <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                                <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                                    Client
                                </p>

                                <p className="mt-1 text-sm font-semibold text-zinc-950">
                                    {clientName}
                                </p>

                                <p className="mt-1 text-sm text-zinc-500">
                                    Identifiant #{clientId}
                                </p>
                            </div>

                            <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
                                <p className="text-xs font-medium uppercase tracking-wide text-emerald-700">
                                    Total encaissé
                                </p>

                                <InvoiceAmount
                                    amount={summary.totalRevenue}
                                    variant="success"
                                    className="mt-2 block text-2xl"
                                />
                            </div>

                            <div className="rounded-2xl border border-blue-200 bg-blue-50 p-4">
                                <p className="text-xs font-medium uppercase tracking-wide text-blue-700">
                                    Montant à encaisser
                                </p>

                                <InvoiceAmount
                                    amount={summary.pendingAmount}
                                    variant="strong"
                                    className="mt-2 block text-2xl text-blue-700"
                                />
                            </div>
                        </div>
                    </HmsCard>

                    <HmsCard>
                        <h3 className="text-sm font-semibold text-zinc-950">
                            Dernière facture
                        </h3>

                        {latestInvoice ? (
                            <div className="mt-5 space-y-4">
                                <div className="flex items-center justify-between gap-3">
                                    <Link
                                        href={`/invoices/${latestInvoice.id}`}
                                        className="text-sm font-semibold text-zinc-950 transition hover:text-stone-700"
                                    >
                                        {latestInvoice.invoiceNumber}
                                    </Link>

                                    <InvoiceStatusBadge
                                        status={latestInvoice.status}
                                    />
                                </div>

                                <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                                    <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                                        Montant TTC
                                    </p>

                                    <InvoiceAmount
                                        amount={latestInvoice.totalAmount}
                                        variant="strong"
                                        className="mt-2 block text-xl"
                                    />

                                    <p className="mt-2 text-sm text-zinc-500">
                                        Créée le{" "}
                                        <InvoiceDate
                                            value={latestInvoice.createdAt}
                                            className="text-sm text-zinc-500"
                                        />
                                    </p>
                                </div>

                                <Link
                                    href={`/invoices/${latestInvoice.id}`}
                                    className="inline-flex w-full items-center justify-center rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50"
                                >
                                    Voir le détail
                                </Link>
                            </div>
                        ) : (
                            <div className="mt-5 rounded-2xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-500">
                                Aucune facture récente pour ce client.
                            </div>
                        )}
                    </HmsCard>
                </div>
            </div>
        </div>
    );
}

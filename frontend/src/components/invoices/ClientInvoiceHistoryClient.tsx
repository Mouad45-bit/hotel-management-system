"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
    ArrowLeft,
    TriangleAlert,
} from "lucide-react";
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
        const timeoutId = window.setTimeout(() => {
            void loadClientInvoices();
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, [clientId]);

    return (
        <div className="space-y-8">
            <section>
                <div>
                    <Link
                        href="/invoices"
                        className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                        Retour aux factures
                    </Link>

                    <h2 className="mt-6 text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                        Historique des factures
                    </h2>

                    <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                        Consultation des factures, paiements, remboursements et montants liés à {clientName}.
                    </p>
                </div>
            </section>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />

                    <div>
                        <p className="font-semibold">Erreur de chargement</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <ClientInvoiceSummaryCards summary={summary} loading={isLoading} />

            <div className="space-y-6">
                <HmsCard className="overflow-hidden p-0">
                    <div className="flex justify-end border-b border-[var(--hms-soft-border)] px-3 py-3">
                        <span className="w-fit rounded-full border border-[var(--hms-soft-border)] bg-slate-50 px-2.5 py-1.5 text-xs font-semibold text-[var(--hms-text-muted)]">
                            {isLoading
                                ? "Chargement"
                                : `${summary.totalInvoices} ${summary.totalInvoices > 1 ? "résultats" : "résultat"}`}
                        </span>
                    </div>

                    <ClientInvoiceHistoryTable
                        invoices={sortedInvoices}
                        loading={isLoading}
                    />
                </HmsCard>

                <div className="space-y-6">
                    <HmsCard className="p-6">
                        <h3 className="text-lg font-bold text-[var(--hms-text)]">
                            Synthèse client
                        </h3>

                        <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                            Vue rapide du comportement de facturation.
                        </p>

                        {isLoading ? (
                            <div className="mt-5 space-y-4">
                                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                    <div className="h-4 w-20 animate-pulse rounded-lg bg-slate-100" />
                                    <div className="mt-3 h-5 w-36 animate-pulse rounded-lg bg-slate-100" />
                                    <div className="mt-2 h-4 w-28 animate-pulse rounded-lg bg-slate-100" />
                                </div>

                                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                    <div className="h-4 w-28 animate-pulse rounded-lg bg-slate-100" />
                                    <div className="mt-3 h-7 w-32 animate-pulse rounded-lg bg-slate-100" />
                                </div>

                                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                    <div className="h-4 w-32 animate-pulse rounded-lg bg-slate-100" />
                                    <div className="mt-3 h-7 w-32 animate-pulse rounded-lg bg-slate-100" />
                                </div>
                            </div>
                        ) : (
                            <div className="mt-5 space-y-4">
                                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                        Client
                                    </p>

                                    <p className="mt-2 text-sm font-bold text-[var(--hms-text)]">
                                        {clientName}
                                    </p>

                                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                                        Identifiant #{clientId}
                                    </p>
                                </div>

                                <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700">
                                        Total encaissé
                                    </p>

                                    <InvoiceAmount
                                        amount={summary.totalRevenue}
                                        variant="success"
                                        className="mt-2 block text-2xl"
                                    />
                                </div>

                                <div className="rounded-2xl border border-blue-200 bg-blue-50 p-4">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-blue-700">
                                        Montant à encaisser
                                    </p>

                                    <InvoiceAmount
                                        amount={summary.pendingAmount}
                                        variant="strong"
                                        className="mt-2 block text-2xl text-blue-700"
                                    />
                                </div>
                            </div>
                        )}
                    </HmsCard>

                    <HmsCard className="p-6">
                        <h3 className="text-lg font-bold text-[var(--hms-text)]">
                            Dernière facture
                        </h3>

                        {isLoading ? (
                            <div className="mt-5 space-y-4">
                                <div className="flex items-center justify-between gap-3">
                                    <div className="h-5 w-36 animate-pulse rounded-lg bg-slate-100" />
                                    <div className="h-6 w-24 animate-pulse rounded-full bg-slate-100" />
                                </div>

                                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                    <div className="h-4 w-24 animate-pulse rounded-lg bg-slate-100" />
                                    <div className="mt-3 h-7 w-32 animate-pulse rounded-lg bg-slate-100" />
                                    <div className="mt-3 h-4 w-40 animate-pulse rounded-lg bg-slate-100" />
                                </div>

                                <div className="h-11 w-full animate-pulse rounded-xl bg-slate-100" />
                            </div>
                        ) : latestInvoice ? (
                            <div className="mt-5 space-y-4">
                                <div className="flex items-center justify-between gap-3">
                                    <Link
                                        href={`/invoices/${latestInvoice.id}`}
                                        className="cursor-pointer text-sm font-bold text-[var(--hms-text)] transition-colors hover:text-[var(--hms-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                    >
                                        {latestInvoice.invoiceNumber}
                                    </Link>

                                    <InvoiceStatusBadge
                                        status={latestInvoice.status}
                                    />
                                </div>

                                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-[var(--hms-text-muted)]">
                                        Montant TTC
                                    </p>

                                    <InvoiceAmount
                                        amount={latestInvoice.totalAmount}
                                        variant="strong"
                                        className="mt-2 block text-xl"
                                    />

                                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                                        Créée le{" "}
                                        <InvoiceDate
                                            value={latestInvoice.createdAt}
                                            className="text-sm text-[var(--hms-text-muted)]"
                                        />
                                    </p>
                                </div>

                                <Link
                                    href={`/invoices/${latestInvoice.id}`}
                                    className="inline-flex min-h-11 w-full cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                >
                                    Voir le détail
                                </Link>
                            </div>
                        ) : (
                            <div className="mt-5 rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm text-[var(--hms-text-muted)]">
                                Aucune facture récente pour ce client.
                            </div>
                        )}
                    </HmsCard>
                </div>
            </div>
        </div>
    );
}

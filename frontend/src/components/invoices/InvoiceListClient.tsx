"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowPathIcon,
    DocumentPlusIcon,
    ExclamationTriangleIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceFilters } from "@/components/invoices/InvoiceFilters";
import { InvoiceStatsCards } from "@/components/invoices/InvoiceStatsCards";
import { InvoiceTable } from "@/components/invoices/InvoiceTable";
import {
    getInvoices,
    getInvoiceStats,
} from "@/services/invoiceApi";
import {
    invoiceFiltersSchema,
    toInvoiceSearchParams,
    type InvoiceFiltersFormValues,
} from "@/schemas/invoice.schema";
import {
    DEFAULT_INVOICE_FILTERS,
    type Invoice,
    type InvoiceFiltersState,
    type InvoiceStats,
    type PageResponse,
} from "@/types/invoice";

const PAGE_SIZE = 8;

const EMPTY_STATS: InvoiceStats = {
    total: 0,
    draft: 0,
    issued: 0,
    paid: 0,
    cancelled: 0,
    refunded: 0,
    totalRevenue: 0,
    pendingAmount: 0,
    refundedAmount: 0,
};

type FilterErrors = Partial<Record<keyof InvoiceFiltersState, string>>;

function extractFilterErrors(
    issues: { path: PropertyKey[]; message: string }[]
): FilterErrors {
    const errors: FilterErrors = {};

    issues.forEach((issue) => {
        const field = issue.path[0];

        if (typeof field === "string") {
            errors[field as keyof InvoiceFiltersState] = issue.message;
        }
    });

    return errors;
}

export function InvoiceListClient() {
    const [filters, setFilters] = useState<InvoiceFiltersState>(
        DEFAULT_INVOICE_FILTERS
    );

    const [filterErrors, setFilterErrors] = useState<FilterErrors>({});

    const [pageResponse, setPageResponse] =
        useState<PageResponse<Invoice> | null>(null);

    const [stats, setStats] = useState<InvoiceStats>(EMPTY_STATS);

    const [currentPage, setCurrentPage] = useState(0);

    const [isLoading, setIsLoading] = useState(true);

    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadInvoices(
        nextFilters: InvoiceFiltersState,
        page: number
    ) {
        const validationResult = invoiceFiltersSchema.safeParse(nextFilters);

        if (!validationResult.success) {
            setFilterErrors(extractFilterErrors(validationResult.error.issues));
            return;
        }

        setIsLoading(true);
        setErrorMessage(null);
        setFilterErrors({});

        try {
            const searchParams = toInvoiceSearchParams(
                validationResult.data as InvoiceFiltersFormValues
            );

            const [invoicesPage, invoiceStats] = await Promise.all([
                getInvoices({
                    ...searchParams,
                    page,
                    size: PAGE_SIZE,
                    sort: "createdAt,desc",
                }),
                getInvoiceStats(),
            ]);

            setPageResponse(invoicesPage);
            setStats(invoiceStats);
            setCurrentPage(invoicesPage.page);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger les factures."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            void loadInvoices(DEFAULT_INVOICE_FILTERS, 0);
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, []);

    function handleApplyFilters(nextFilters: InvoiceFiltersState) {
        setFilters(nextFilters);
        void loadInvoices(nextFilters, 0);
    }

    function handleResetFilters() {
        setFilters(DEFAULT_INVOICE_FILTERS);
        void loadInvoices(DEFAULT_INVOICE_FILTERS, 0);
    }

    function handlePreviousPage() {
        if (currentPage === 0) {
            return;
        }

        void loadInvoices(filters, currentPage - 1);
    }

    function handleNextPage() {
        if (!pageResponse || pageResponse.last) {
            return;
        }

        void loadInvoices(filters, currentPage + 1);
    }

    const invoices = pageResponse?.content ?? [];

    return (
        <div className="space-y-6">
            <HmsCard>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <p className="text-sm font-medium text-stone-700">
                            Module Invoice
                        </p>

                        <h2 className="mt-2 text-xl font-semibold tracking-tight text-zinc-950">
                            Liste des factures
                        </h2>

                        <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-500">
                            Suivez les factures générées depuis les réservations,
                            leurs statuts de paiement, les montants encaissés et les
                            remboursements.
                        </p>
                    </div>

                    <Link
                        href="/invoices/create"
                        className="inline-flex items-center justify-center gap-2 rounded-xl bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800"
                    >
                        <DocumentPlusIcon className="h-5 w-5" />
                        Générer une facture
                    </Link>
                </div>
            </HmsCard>

            <InvoiceStatsCards stats={stats} loading={isLoading} />

            <InvoiceFilters
                filters={filters}
                errors={filterErrors}
                loading={isLoading}
                onApply={handleApplyFilters}
                onReset={handleResetFilters}
            />

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />

                    <div>
                        <p className="font-semibold">Erreur de chargement</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <HmsCard className="p-0">
                <div className="flex flex-col gap-3 border-b border-zinc-200 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                        <h3 className="text-sm font-semibold text-zinc-950">
                            Tableau des factures
                        </h3>

                        <p className="mt-1 text-sm text-zinc-500">
                            {pageResponse
                                ? `${pageResponse.totalElements} facture(s) trouvée(s)`
                                : "Chargement des factures"}
                        </p>
                    </div>

                    <button
                        type="button"
                        onClick={() => void loadInvoices(filters, currentPage)}
                        disabled={isLoading}
                        className="inline-flex items-center justify-center gap-2 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        <ArrowPathIcon className="h-4 w-4" />
                        Actualiser
                    </button>
                </div>

                <InvoiceTable
                    invoices={invoices}
                    loading={isLoading}
                    emptyMessage="Aucune facture ne correspond aux filtres."
                />

                <div className="flex items-center justify-between border-t border-zinc-200 px-6 py-4">
                    <p className="text-sm text-zinc-500">
                        Page{" "}
                        <span className="font-medium text-zinc-900">
                            {pageResponse ? pageResponse.page + 1 : 1}
                        </span>{" "}
                        sur{" "}
                        <span className="font-medium text-zinc-900">
                            {pageResponse?.totalPages || 1}
                        </span>
                    </p>

                    <div className="flex items-center gap-2">
                        <button
                            type="button"
                            onClick={handlePreviousPage}
                            disabled={isLoading || currentPage === 0}
                            className="rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                            Précédent
                        </button>

                        <button
                            type="button"
                            onClick={handleNextPage}
                            disabled={
                                isLoading ||
                                !pageResponse ||
                                pageResponse.last
                            }
                            className="rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                            Suivant
                        </button>
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}

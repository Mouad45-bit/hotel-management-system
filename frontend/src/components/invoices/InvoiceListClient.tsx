"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    Plus,
    RefreshCw,
    TriangleAlert,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { PageHeader } from "@/components/layout/PageHeader";
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
        <div className="space-y-8">
            <PageHeader
                title="Facturation"
                description="Gestion, suivi et traitement des factures liées aux réservations."
                actions={
                    <Link href="/invoices/create">
                        <HmsButton>
                            <Plus aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                            Générer une facture
                        </HmsButton>
                    </Link>
                }
            />

            <InvoiceStatsCards stats={stats} loading={isLoading} />

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />

                    <div>
                        <p className="font-semibold">Erreur de chargement</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <HmsCard className="overflow-hidden p-0">
                <div className="flex flex-col gap-2 border-b border-[var(--hms-soft-border)] px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                        <p className="text-sm font-semibold text-[var(--hms-text-muted)]">
                            {pageResponse
                                ? `${pageResponse.totalElements} facture(s) trouvée(s)`
                                : "Chargement des factures"}
                        </p>
                    </div>

                    <div className="flex items-center gap-1.5">
                        <HmsButton
                            type="button"
                            variant="secondary"
                            onClick={handleResetFilters}
                            disabled={isLoading}
                        >
                            <RefreshCw aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                            Actualiser
                        </HmsButton>

                        <InvoiceFilters
                            filters={filters}
                            errors={filterErrors}
                            onApply={handleApplyFilters}
                        />
                    </div>
                </div>

                <InvoiceTable
                    invoices={invoices}
                    loading={isLoading}
                    emptyMessage="Aucune facture ne correspond aux filtres."
                />

                <div className="flex items-center justify-between border-t border-[var(--hms-soft-border)] px-6 py-5">
                    <p className="text-sm text-[var(--hms-text-muted)]">
                        Page{" "}
                        <span className="font-medium text-[var(--hms-text)]">
                            {pageResponse ? pageResponse.page + 1 : 1}
                        </span>{" "}
                        sur{" "}
                        <span className="font-medium text-[var(--hms-text)]">
                            {pageResponse?.totalPages || 1}
                        </span>
                    </p>

                    <div className="flex items-center gap-2">
                        <HmsButton
                            type="button"
                            variant="secondary"
                            onClick={handlePreviousPage}
                            disabled={isLoading || currentPage === 0}
                            className="min-h-10 px-3"
                        >
                            Précédent
                        </HmsButton>

                        <HmsButton
                            type="button"
                            variant="secondary"
                            onClick={handleNextPage}
                            disabled={
                                isLoading ||
                                !pageResponse ||
                                pageResponse.last
                            }
                            className="min-h-10 px-3"
                        >
                            Suivant
                        </HmsButton>
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}

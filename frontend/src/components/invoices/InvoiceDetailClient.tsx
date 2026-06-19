"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowLeftIcon,
    ExclamationTriangleIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceActionPanel } from "@/components/invoices/InvoiceActionPanel";
import { InvoiceDetailHeader } from "@/components/invoices/InvoiceDetailHeader";
import { InvoiceFinancialSummary } from "@/components/invoices/InvoiceFinancialSummary";
import { InvoiceInfoCards } from "@/components/invoices/InvoiceInfoCards";
import { InvoiceLinesTable } from "@/components/invoices/InvoiceLinesTable";
import { InvoiceTimeline } from "@/components/invoices/InvoiceTimeline";
import { getInvoiceById } from "@/services/invoiceApi";
import type { Invoice } from "@/types/invoice";

interface InvoiceDetailClientProps {
    invoiceId: number;
}

export function InvoiceDetailClient({ invoiceId }: InvoiceDetailClientProps) {
    const [invoice, setInvoice] = useState<Invoice | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadInvoice() {
        if (!Number.isFinite(invoiceId) || invoiceId <= 0) {
            setInvoice(null);
            setErrorMessage("Identifiant de facture invalide.");
            setIsLoading(false);
            return;
        }

        setIsLoading(true);
        setErrorMessage(null);

        try {
            const loadedInvoice = await getInvoiceById(invoiceId);
            setInvoice(loadedInvoice);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger la facture."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        void loadInvoice();
    }, [invoiceId]);

    if (isLoading) {
        return (
            <div className="space-y-6">
                <HmsCard>
                    <div className="h-6 w-48 animate-pulse rounded-lg bg-zinc-100" />
                    <div className="mt-4 h-10 w-80 animate-pulse rounded-lg bg-zinc-100" />
                </HmsCard>

                <div className="grid gap-6 xl:grid-cols-[1fr_360px]">
                    <div className="space-y-6">
                        <HmsCard>
                            <div className="h-52 animate-pulse rounded-xl bg-zinc-100" />
                        </HmsCard>

                        <HmsCard>
                            <div className="h-64 animate-pulse rounded-xl bg-zinc-100" />
                        </HmsCard>
                    </div>

                    <div className="space-y-6">
                        <HmsCard>
                            <div className="h-48 animate-pulse rounded-xl bg-zinc-100" />
                        </HmsCard>

                        <HmsCard>
                            <div className="h-48 animate-pulse rounded-xl bg-zinc-100" />
                        </HmsCard>
                    </div>
                </div>
            </div>
        );
    }

    if (errorMessage || !invoice) {
        return (
            <div className="space-y-6">
                <Link
                    href="/invoices"
                    className="inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                >
                    <ArrowLeftIcon className="h-4 w-4" />
                    Retour aux factures
                </Link>

                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />

                    <div>
                        <p className="font-semibold">Facture introuvable</p>
                        <p className="mt-1">
                            {errorMessage ?? "Impossible d’afficher cette facture."}
                        </p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <InvoiceDetailHeader invoice={invoice} />

            <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
                <div className="space-y-6">
                    <InvoiceFinancialSummary invoice={invoice} />

                    <InvoiceLinesTable invoice={invoice} />

                    <InvoiceInfoCards invoice={invoice} />
                </div>

                <div className="space-y-6">
                    <InvoiceActionPanel
                        invoice={invoice}
                        onInvoiceUpdated={setInvoice}
                    />

                    <InvoiceTimeline invoice={invoice} />
                </div>
            </div>
        </div>
    );
}

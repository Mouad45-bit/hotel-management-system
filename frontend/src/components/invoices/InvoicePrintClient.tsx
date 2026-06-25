"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowLeft,
    Printer,
    TriangleAlert,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { InvoicePrintableDocument } from "@/components/invoices/InvoicePrintableDocument";
import { InvoiceStatusBadge } from "@/components/invoices/InvoiceStatusBadge";
import { canPrintInvoice } from "@/lib/invoiceHelpers";
import { getInvoiceById } from "@/services/invoiceApi";
import type { Invoice } from "@/types/invoice";

interface InvoicePrintClientProps {
    invoiceId: number;
}

export function InvoicePrintClient({ invoiceId }: InvoicePrintClientProps) {
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
        const timeoutId = window.setTimeout(() => {
            void loadInvoice();
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, [invoiceId]);

    function handlePrint() {
        window.print();
    }

    const printable = invoice ? canPrintInvoice(invoice) : false;

    return (
        <div className="hms-print-page min-h-screen overflow-x-hidden bg-[var(--hms-page)]">
            <div className="hms-print-toolbar sticky top-0 z-20 border-b border-[var(--hms-soft-border)] bg-white px-4 py-4 sm:px-6">
                <div className="mx-auto flex max-w-[1180px] flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
                        <Link
                            href={invoice ? `/invoices/${invoice.id}` : "/invoices"}
                            className="inline-flex min-h-11 w-fit cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                        >
                            <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                            Retour
                        </Link>

                        <div className="hidden h-11 w-px bg-[var(--hms-soft-border)] sm:block" />

                        <div>
                            <p className="text-base font-bold tracking-tight text-[var(--hms-text)]">
                                Aperçu imprimable
                            </p>

                            <p className="mt-1 max-w-xl text-sm leading-6 text-[var(--hms-text-muted)]">
                                Utilisez le bouton Imprimer / PDF pour enregistrer la facture.
                            </p>
                        </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 lg:justify-end">
                        {invoice && <InvoiceStatusBadge status={invoice.status} />}

                        <HmsButton
                            type="button"
                            onClick={handlePrint}
                            disabled={!invoice || !printable || isLoading}
                        >
                            <Printer aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                            Imprimer / PDF
                        </HmsButton>
                    </div>
                </div>
            </div>

            <main className="hms-print-canvas mx-auto flex w-full flex-col items-center px-4 py-8 sm:px-6 lg:py-10 print:block print:p-0">
                {isLoading && (
                    <div className="hms-print-document min-h-[297mm] w-[210mm] max-w-full rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-8 shadow-[0_18px_55px_rgba(13,9,7,0.06)] sm:p-10">
                        <div className="space-y-8">
                            <div className="flex items-start justify-between gap-8">
                                <div className="space-y-4">
                                    <div className="h-12 w-12 rounded-2xl bg-slate-100" />
                                    <div className="h-5 w-56 rounded-lg bg-slate-100" />
                                    <div className="h-4 w-72 max-w-full rounded-lg bg-slate-100" />
                                </div>

                                <div className="hidden space-y-3 text-right sm:block">
                                    <div className="h-4 w-24 rounded-lg bg-slate-100" />
                                    <div className="h-8 w-44 rounded-lg bg-slate-100" />
                                    <div className="ml-auto h-6 w-24 rounded-full bg-slate-100" />
                                </div>
                            </div>

                            <div className="grid gap-6 border-y border-[var(--hms-soft-border)] py-8 sm:grid-cols-2">
                                <div className="h-28 rounded-2xl bg-slate-50" />
                                <div className="h-28 rounded-2xl bg-slate-50" />
                            </div>

                            <div className="space-y-3">
                                {Array.from({ length: 6 }).map((_, index) => (
                                    <div
                                        key={index}
                                        className="h-12 rounded-xl bg-slate-50"
                                    />
                                ))}
                            </div>
                        </div>
                    </div>
                )}

                {!isLoading && errorMessage && (
                    <div className="hms-print-alert w-full max-w-[720px] rounded-2xl border border-red-200 bg-red-50 p-5 text-sm text-red-700 shadow-[0_16px_40px_rgba(13,9,7,0.03)]">
                        <div className="flex items-start gap-3">
                            <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />

                            <div>
                                <p className="font-semibold">
                                    Impossible d’afficher l’aperçu
                                </p>

                                <p className="mt-1">{errorMessage}</p>
                            </div>
                        </div>
                    </div>
                )}

                {!isLoading && invoice && !printable && (
                    <div className="hms-print-alert mb-6 w-[210mm] max-w-full rounded-2xl border border-amber-200 bg-amber-50 p-5 text-sm text-amber-800 shadow-[0_16px_40px_rgba(13,9,7,0.03)]">
                        <div className="flex items-start gap-3">
                            <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />

                            <div>
                                <p className="font-semibold">
                                    Facture non imprimable
                                </p>

                                <p className="mt-1">
                                    Cette facture n’est pas dans un statut prévu
                                    pour l’impression. L’aperçu reste visible pour
                                    contrôle, mais le bouton d’impression est désactivé.
                                </p>
                            </div>
                        </div>
                    </div>
                )}

                {!isLoading && invoice && (
                    <InvoicePrintableDocument invoice={invoice} />
                )}
            </main>
        </div>
    );
}

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
        <div className="hms-print-page min-h-screen bg-[var(--hms-page)]">
            <div className="hms-print-toolbar sticky top-0 z-20 border-b border-[var(--hms-soft-border)] bg-white px-6 py-4">
                <div className="mx-auto flex max-w-5xl flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div className="flex items-start gap-3">
                        <Link
                            href={invoice ? `/invoices/${invoice.id}` : "/invoices"}
                            className="mt-1 inline-flex cursor-pointer items-center gap-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:text-[var(--hms-primary)]"
                        >
                            <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                            Retour
                        </Link>

                        <div className="hidden h-6 w-px bg-zinc-200 sm:block" />

                        <div>
                            <p className="text-sm font-bold text-[var(--hms-text)]">
                                Aperçu imprimable
                            </p>

                            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                                Utilisez le bouton Imprimer puis choisissez
                                “Enregistrer en PDF” dans le navigateur.
                            </p>
                        </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-3">
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

            <main className="mx-auto max-w-[210mm] px-4 py-8 print:p-0">
                {isLoading && (
                    <div className="hms-print-document min-h-[297mm] rounded-2xl bg-white p-10 shadow-[0_16px_40px_rgba(13,9,7,0.06)] ring-1 ring-[var(--hms-soft-border)]">
                        <div className="space-y-6">
                            <div className="h-8 w-60 animate-pulse rounded-lg bg-slate-100" />
                            <div className="h-24 animate-pulse rounded-xl bg-slate-100" />
                            <div className="h-96 animate-pulse rounded-xl bg-slate-100" />
                        </div>
                    </div>
                )}

                {!isLoading && errorMessage && (
                    <div className="hms-print-alert rounded-2xl border border-red-200 bg-red-50 p-5 text-sm text-red-700">
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
                    <div className="hms-print-alert mb-6 rounded-2xl border border-amber-200 bg-amber-50 p-5 text-sm text-amber-800">
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

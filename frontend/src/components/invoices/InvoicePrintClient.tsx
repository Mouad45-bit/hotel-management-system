"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowLeftIcon,
    ExclamationTriangleIcon,
    PrinterIcon,
} from "@heroicons/react/24/outline";
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
        void loadInvoice();
    }, [invoiceId]);

    function handlePrint() {
        window.print();
    }

    const printable = invoice ? canPrintInvoice(invoice) : false;

    return (
        <div className="hms-print-page min-h-screen bg-zinc-100">
            <div className="hms-print-toolbar sticky top-0 z-20 border-b border-zinc-200 bg-white/95 px-6 py-4 backdrop-blur">
                <div className="mx-auto flex max-w-5xl flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div className="flex items-start gap-3">
                        <Link
                            href={invoice ? `/invoices/${invoice.id}` : "/invoices"}
                            className="mt-1 inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                        >
                            <ArrowLeftIcon className="h-4 w-4" />
                            Retour
                        </Link>

                        <div className="hidden h-6 w-px bg-zinc-200 sm:block" />

                        <div>
                            <p className="text-sm font-semibold text-zinc-950">
                                Aperçu imprimable
                            </p>

                            <p className="mt-1 text-sm text-zinc-500">
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
                            <PrinterIcon className="mr-2 h-5 w-5" />
                            Imprimer / PDF
                        </HmsButton>
                    </div>
                </div>
            </div>

            <main className="mx-auto max-w-[210mm] px-4 py-8 print:p-0">
                {isLoading && (
                    <div className="hms-print-document min-h-[297mm] rounded-2xl bg-white p-10 shadow-xl ring-1 ring-zinc-200">
                        <div className="space-y-6">
                            <div className="h-8 w-60 animate-pulse rounded-lg bg-zinc-100" />
                            <div className="h-24 animate-pulse rounded-xl bg-zinc-100" />
                            <div className="h-96 animate-pulse rounded-xl bg-zinc-100" />
                        </div>
                    </div>
                )}

                {!isLoading && errorMessage && (
                    <div className="hms-print-alert rounded-2xl border border-red-200 bg-red-50 p-5 text-sm text-red-700">
                        <div className="flex items-start gap-3">
                            <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />

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
                            <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />

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

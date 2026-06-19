"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
    ArrowLeftIcon,
    CheckCircleIcon,
    DocumentPlusIcon,
    ExclamationTriangleIcon,
    ReceiptPercentIcon,
} from "@heroicons/react/24/outline";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import { ReservationInvoiceSourceTable } from "@/components/invoices/ReservationInvoiceSourceTable";
import {
    generateInvoiceFromReservation,
    getReservationInvoiceSources,
} from "@/services/invoiceApi";
import { generateInvoiceSchema } from "@/schemas/invoice.schema";
import type { ReservationInvoiceSource } from "@/types/invoice";

interface GenerateInvoiceFormState {
    taxRate: string;
    notes: string;
}

type GenerateInvoiceField = "reservationId" | "taxRate" | "notes";

type GenerateInvoiceErrors = Partial<Record<GenerateInvoiceField, string>>;

const DEFAULT_FORM: GenerateInvoiceFormState = {
    taxRate: "10",
    notes: "Facture générée après check-out",
};

function roundMoney(value: number): number {
    return Math.round(value * 100) / 100;
}

function extractErrors(
    issues: { path: PropertyKey[]; message: string }[]
): GenerateInvoiceErrors {
    const errors: GenerateInvoiceErrors = {};

    issues.forEach((issue) => {
        const field = issue.path[0];

        if (typeof field === "string") {
            errors[field as GenerateInvoiceField] = issue.message;
        }
    });

    return errors;
}

function calculatePreviewAmounts(
    source: ReservationInvoiceSource | null,
    taxRateValue: string
) {
    if (!source) {
        return {
            subtotalAmount: 0,
            taxAmount: 0,
            totalAmount: 0,
        };
    }

    const taxRate = Number(taxRateValue);
    const safeTaxRate = Number.isFinite(taxRate) && taxRate >= 0 ? taxRate : 0;

    const subtotalAmount = roundMoney(source.nights * source.pricePerNight);
    const taxAmount = roundMoney((subtotalAmount * safeTaxRate) / 100);
    const totalAmount = roundMoney(subtotalAmount + taxAmount);

    return {
        subtotalAmount,
        taxAmount,
        totalAmount,
    };
}

export function InvoiceCreateClient() {
    const router = useRouter();

    const [reservationSources, setReservationSources] = useState<
        ReservationInvoiceSource[]
    >([]);

    const [selectedReservation, setSelectedReservation] =
        useState<ReservationInvoiceSource | null>(null);

    const [form, setForm] = useState<GenerateInvoiceFormState>(DEFAULT_FORM);

    const [errors, setErrors] = useState<GenerateInvoiceErrors>({});

    const [isLoading, setIsLoading] = useState(true);

    const [isSubmitting, setIsSubmitting] = useState(false);

    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    const [successMessage, setSuccessMessage] = useState<string | null>(null);

    async function loadReservationSources() {
        setIsLoading(true);
        setErrorMessage(null);

        try {
            const sources = await getReservationInvoiceSources();
            setReservationSources(sources);

            const firstAvailableSource = sources.find(
                (source) =>
                    source.reservationStatus === "CHECKED_OUT" &&
                    !source.hasActiveInvoice
            );

            setSelectedReservation(firstAvailableSource ?? null);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger les réservations."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        void loadReservationSources();
    }, []);

    function updateFormField<K extends keyof GenerateInvoiceFormState>(
        field: K,
        value: GenerateInvoiceFormState[K]
    ) {
        setForm((current) => ({
            ...current,
            [field]: value,
        }));
    }

    function handleSelectReservation(source: ReservationInvoiceSource) {
        if (
            source.reservationStatus !== "CHECKED_OUT" ||
            source.hasActiveInvoice
        ) {
            return;
        }

        setSelectedReservation(source);
        setErrors({});
        setErrorMessage(null);
        setSuccessMessage(null);
    }

    async function handleSubmit() {
        setErrorMessage(null);
        setSuccessMessage(null);

        if (!selectedReservation) {
            setErrors({
                reservationId:
                    "Sélectionnez une réservation terminée sans facture active.",
            });
            return;
        }

        const validationResult = generateInvoiceSchema.safeParse({
            reservationId: selectedReservation.reservationId,
            taxRate: form.taxRate,
            notes: form.notes,
        });

        if (!validationResult.success) {
            setErrors(extractErrors(validationResult.error.issues));
            return;
        }

        setErrors({});
        setIsSubmitting(true);

        try {
            const createdInvoice = await generateInvoiceFromReservation(
                validationResult.data.reservationId,
                {
                    taxRate: validationResult.data.taxRate,
                    notes: validationResult.data.notes,
                }
            );

            setSuccessMessage(
                `La facture ${createdInvoice.invoiceNumber} a été générée.`
            );

            router.push(`/invoices/${createdInvoice.id}`);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de générer la facture."
            );
        } finally {
            setIsSubmitting(false);
        }
    }

    const previewAmounts = calculatePreviewAmounts(
        selectedReservation,
        form.taxRate
    );

    return (
        <div className="space-y-6">
            <HmsCard>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div>
                        <Link
                            href="/invoices"
                            className="inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                        >
                            <ArrowLeftIcon className="h-4 w-4" />
                            Retour aux factures
                        </Link>

                        <div className="mt-5 flex items-center gap-3">
                            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-stone-900 text-white">
                                <DocumentPlusIcon className="h-5 w-5" />
                            </div>

                            <div>
                                <h2 className="text-2xl font-semibold tracking-tight text-zinc-950">
                                    Génération depuis réservation
                                </h2>

                                <p className="mt-1 text-sm text-zinc-500">
                                    Choisissez une réservation terminée, appliquez
                                    le taux de taxe, puis générez la facture.
                                </p>
                            </div>
                        </div>
                    </div>

                    <div className="rounded-2xl border border-stone-200 bg-stone-50 px-4 py-3 text-sm text-stone-700">
                        <p className="font-semibold">Règle V1</p>
                        <p className="mt-1">
                            Seules les réservations terminées sans facture active
                            peuvent être facturées.
                        </p>
                    </div>
                </div>
            </HmsCard>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />

                    <div>
                        <p className="font-semibold">Erreur</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            {successMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">
                    <CheckCircleIcon className="mt-0.5 h-5 w-5 shrink-0" />

                    <div>
                        <p className="font-semibold">Facture générée</p>
                        <p className="mt-1">{successMessage}</p>
                    </div>
                </div>
            )}

            <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
                <HmsCard className="p-0">
                    <div className="border-b border-zinc-200 px-6 py-4">
                        <h3 className="text-sm font-semibold text-zinc-950">
                            Réservations disponibles
                        </h3>

                        <p className="mt-1 text-sm text-zinc-500">
                            Les données sont simulées tant que le module
                            Reservation n’est pas encore branché.
                        </p>
                    </div>

                    {isLoading ? (
                        <div className="divide-y divide-zinc-100">
                            {Array.from({ length: 5 }).map((_, index) => (
                                <div
                                    key={index}
                                    className="grid gap-4 px-6 py-4 md:grid-cols-5"
                                >
                                    {Array.from({ length: 5 }).map(
                                        (__, cellIndex) => (
                                            <div
                                                key={cellIndex}
                                                className="h-5 animate-pulse rounded-lg bg-zinc-100"
                                            />
                                        )
                                    )}
                                </div>
                            ))}
                        </div>
                    ) : (
                        <ReservationInvoiceSourceTable
                            sources={reservationSources}
                            selectedReservationId={
                                selectedReservation?.reservationId ?? null
                            }
                            onSelect={handleSelectReservation}
                        />
                    )}

                    {errors.reservationId && (
                        <div className="border-t border-red-100 bg-red-50 px-6 py-3 text-sm text-red-700">
                            {errors.reservationId}
                        </div>
                    )}
                </HmsCard>

                <div className="space-y-6">
                    <HmsCard>
                        <div className="flex items-start justify-between gap-4">
                            <div>
                                <h3 className="text-sm font-semibold text-zinc-950">
                                    Paramètres de génération
                                </h3>

                                <p className="mt-1 text-sm text-zinc-500">
                                    Ces informations seront envoyées au service
                                    Invoice.
                                </p>
                            </div>

                            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-stone-100 text-stone-700">
                                <ReceiptPercentIcon className="h-5 w-5" />
                            </div>
                        </div>

                        <div className="mt-5 space-y-4">
                            <div>
                                <label className="text-xs font-medium text-zinc-600">
                                    Taux de taxe (%)
                                </label>

                                <input
                                    type="number"
                                    min="0"
                                    step="0.01"
                                    value={form.taxRate}
                                    onChange={(event) =>
                                        updateFormField(
                                            "taxRate",
                                            event.target.value
                                        )
                                    }
                                    className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                />

                                {errors.taxRate && (
                                    <p className="mt-1 text-xs text-red-600">
                                        {errors.taxRate}
                                    </p>
                                )}
                            </div>

                            <div>
                                <label className="text-xs font-medium text-zinc-600">
                                    Notes
                                </label>

                                <textarea
                                    value={form.notes}
                                    onChange={(event) =>
                                        updateFormField(
                                            "notes",
                                            event.target.value
                                        )
                                    }
                                    rows={4}
                                    placeholder="Facture générée après check-out"
                                    className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                />

                                {errors.notes && (
                                    <p className="mt-1 text-xs text-red-600">
                                        {errors.notes}
                                    </p>
                                )}
                            </div>

                            <HmsButton
                                type="button"
                                onClick={() => void handleSubmit()}
                                disabled={isSubmitting || !selectedReservation}
                                className="w-full"
                            >
                                {isSubmitting
                                    ? "Génération..."
                                    : "Générer la facture"}
                            </HmsButton>
                        </div>
                    </HmsCard>

                    <HmsCard>
                        <h3 className="text-sm font-semibold text-zinc-950">
                            Aperçu
                        </h3>

                        <p className="mt-1 text-sm text-zinc-500">
                            Estimation avant création définitive.
                        </p>

                        {selectedReservation ? (
                            <div className="mt-5 space-y-5">
                                <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                                    <p className="text-sm font-semibold text-zinc-950">
                                        {selectedReservation.clientFullName}
                                    </p>

                                    <p className="mt-1 text-sm text-zinc-500">
                                        Réservation #
                                        {selectedReservation.reservationId} ·
                                        Chambre {selectedReservation.roomNumber}
                                    </p>

                                    <p className="mt-2 text-sm text-zinc-500">
                                        <InvoiceDate
                                            value={
                                                selectedReservation.checkInDate
                                            }
                                            className="text-sm text-zinc-500"
                                        />{" "}
                                        →{" "}
                                        <InvoiceDate
                                            value={
                                                selectedReservation.checkOutDate
                                            }
                                            className="text-sm text-zinc-500"
                                        />
                                    </p>
                                </div>

                                <div className="space-y-3 text-sm">
                                    <div className="flex items-center justify-between">
                                        <span className="text-zinc-500">
                                            Nombre de nuits
                                        </span>

                                        <span className="font-medium text-zinc-950">
                                            {selectedReservation.nights}
                                        </span>
                                    </div>

                                    <div className="flex items-center justify-between">
                                        <span className="text-zinc-500">
                                            Prix par nuit
                                        </span>

                                        <InvoiceAmount
                                            amount={
                                                selectedReservation.pricePerNight
                                            }
                                            variant="default"
                                            className="text-sm"
                                        />
                                    </div>

                                    <div className="flex items-center justify-between">
                                        <span className="text-zinc-500">
                                            Montant HT
                                        </span>

                                        <InvoiceAmount
                                            amount={
                                                previewAmounts.subtotalAmount
                                            }
                                            variant="default"
                                            className="text-sm"
                                        />
                                    </div>

                                    <div className="flex items-center justify-between">
                                        <span className="text-zinc-500">
                                            Taxe
                                        </span>

                                        <InvoiceAmount
                                            amount={previewAmounts.taxAmount}
                                            variant="default"
                                            className="text-sm"
                                        />
                                    </div>

                                    <div className="flex items-center justify-between border-t border-zinc-200 pt-3">
                                        <span className="font-semibold text-zinc-950">
                                            Total TTC
                                        </span>

                                        <InvoiceAmount
                                            amount={previewAmounts.totalAmount}
                                            variant="strong"
                                            className="text-xl"
                                        />
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <div className="mt-5 rounded-2xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-500">
                                Sélectionnez une réservation pour afficher
                                l’aperçu de la facture.
                            </div>
                        )}
                    </HmsCard>
                </div>
            </div>
        </div>
    );
}

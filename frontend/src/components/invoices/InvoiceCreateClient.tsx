"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
    ArrowLeft,
    CircleCheckBig,
    FileText,
    TriangleAlert,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HmsInput, HmsTextarea } from "@/components/hms/HmsField";
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
        const timeoutId = window.setTimeout(() => {
            void loadReservationSources();
        }, 0);

        return () => window.clearTimeout(timeoutId);
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

    const eligibleReservationCount = reservationSources.filter(
        (source) =>
            source.reservationStatus === "CHECKED_OUT" &&
            !source.hasActiveInvoice
    ).length;

    return (
        <div className="space-y-8">
            <section>
                <Link
                    href="/invoices"
                    className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    Retour aux factures
                </Link>

                <h2 className="mt-6 text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                    Générer une facture
                </h2>

                <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                    Sélectionnez une réservation terminée,
                    <br className="hidden md:block" />{" "}
                    ajustez les paramètres puis vérifiez le montant avant génération.
                </p>
            </section>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />

                    <div>
                        <p className="font-semibold">Erreur</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            {successMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">
                    <CircleCheckBig aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />

                    <div>
                        <p className="font-semibold">Facture générée</p>
                        <p className="mt-1">{successMessage}</p>
                    </div>
                </div>
            )}

            <div className="space-y-6">
                <HmsCard className="overflow-hidden p-0">
                    <div className="flex flex-col gap-3 border-b border-[var(--hms-soft-border)] px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                            <h3 className="text-lg font-bold text-[var(--hms-text)]">
                                Réservations éligibles
                            </h3>

                            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                                Choisissez la réservation à utiliser comme source de la facture.
                            </p>
                        </div>

                        <span className="w-fit rounded-full border border-[var(--hms-soft-border)] bg-slate-50 px-3 py-1.5 text-xs font-semibold text-[var(--hms-text-muted)]">
                            {isLoading
                                ? "Chargement"
                                : `${eligibleReservationCount} facturable(s)`}
                        </span>
                    </div>

                    {isLoading ? (
                        <div className="divide-y divide-[var(--hms-soft-border)]">
                            {Array.from({ length: 5 }).map((_, index) => (
                                <div
                                    key={index}
                                    className="grid gap-3 px-4 py-4 sm:grid-cols-2 xl:grid-cols-8"
                                >
                                    {Array.from({ length: 8 }).map(
                                        (__, cellIndex) => (
                                            <div
                                                key={cellIndex}
                                                className="h-5 animate-pulse rounded-lg bg-slate-100"
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

                <div className="grid gap-6 xl:grid-cols-2">
                    <HmsCard className="p-6">
                        <div>
                            <h3 className="text-lg font-bold text-[var(--hms-text)]">
                                Paramètres de facturation
                            </h3>

                            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                                Renseignez le taux de taxe et les notes associées à la facture.
                            </p>
                        </div>

                        <div className="mt-6 space-y-5">
                            <HmsInput
                                id="invoice-tax-rate"
                                label="Taux de taxe (%)"
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
                                error={errors.taxRate}
                            />

                            <HmsTextarea
                                id="invoice-notes"
                                label="Notes"
                                value={form.notes}
                                onChange={(event) =>
                                    updateFormField(
                                        "notes",
                                        event.target.value
                                    )
                                }
                                rows={5}
                                placeholder="Facture générée après check-out"
                                error={errors.notes}
                            />
                        </div>
                    </HmsCard>

                    <HmsCard className="p-6">
                        <h3 className="text-lg font-bold text-[var(--hms-text)]">
                            Aperçu financier
                        </h3>

                        <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                            Vérifiez les informations et le montant avant de générer la facture.
                        </p>

                        {selectedReservation ? (
                            <div className="mt-6 space-y-5">
                                <dl className="grid gap-4 rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 sm:grid-cols-2">
                                    <div className="sm:col-span-2">
                                        <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">
                                            Client
                                        </dt>
                                        <dd className="mt-1 text-sm font-bold text-[var(--hms-text)]">
                                            {selectedReservation.clientFullName}
                                        </dd>
                                    </div>

                                    <div>
                                        <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">
                                            Réservation
                                        </dt>
                                        <dd className="mt-1 text-sm font-semibold text-[var(--hms-text)]">
                                            #{selectedReservation.reservationId}
                                        </dd>
                                    </div>

                                    <div>
                                        <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">
                                            Chambre
                                        </dt>
                                        <dd className="mt-1 text-sm font-semibold text-[var(--hms-text)]">
                                            {selectedReservation.roomNumber}
                                        </dd>
                                    </div>

                                    <div className="sm:col-span-2">
                                        <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">
                                            Séjour
                                        </dt>
                                        <dd className="mt-1 flex flex-wrap items-center gap-1 text-sm text-[var(--hms-text)]">
                                            <InvoiceDate
                                                value={selectedReservation.checkInDate}
                                                className="text-sm text-[var(--hms-text)]"
                                            />{" "}
                                            →{" "}
                                            <InvoiceDate
                                                value={selectedReservation.checkOutDate}
                                                className="text-sm text-[var(--hms-text)]"
                                            />
                                        </dd>
                                    </div>
                                </dl>

                                <dl className="space-y-3 text-sm">
                                    <div className="flex items-center justify-between gap-4">
                                        <dt className="text-[var(--hms-text-muted)]">
                                            Nombre de nuits
                                        </dt>
                                        <dd className="font-semibold text-[var(--hms-text)]">
                                            {selectedReservation.nights}
                                        </dd>
                                    </div>

                                    <div className="flex items-center justify-between gap-4">
                                        <dt className="text-[var(--hms-text-muted)]">
                                            Prix par nuit
                                        </dt>
                                        <dd>
                                            <InvoiceAmount
                                                amount={selectedReservation.pricePerNight}
                                                variant="default"
                                                className="text-sm"
                                            />
                                        </dd>
                                    </div>

                                    <div className="flex items-center justify-between gap-4">
                                        <dt className="text-[var(--hms-text-muted)]">
                                            Montant HT
                                        </dt>
                                        <dd>
                                            <InvoiceAmount
                                                amount={previewAmounts.subtotalAmount}
                                                variant="default"
                                                className="text-sm"
                                            />
                                        </dd>
                                    </div>

                                    <div className="flex items-center justify-between gap-4">
                                        <dt className="text-[var(--hms-text-muted)]">
                                            Taxe
                                        </dt>
                                        <dd>
                                            <InvoiceAmount
                                                amount={previewAmounts.taxAmount}
                                                variant="default"
                                                className="text-sm"
                                            />
                                        </dd>
                                    </div>
                                </dl>

                                <div className="flex items-end justify-between gap-4 rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                    <div>
                                        <p className="text-sm font-semibold text-[var(--hms-text)]">
                                            Total TTC
                                        </p>
                                        <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                            Montant final estimé
                                        </p>
                                    </div>

                                    <InvoiceAmount
                                        amount={previewAmounts.totalAmount}
                                        variant="strong"
                                        className="text-2xl tracking-tight"
                                    />
                                </div>
                            </div>
                        ) : (
                            <div className="mt-6 flex min-h-64 items-center justify-center rounded-2xl border border-dashed border-[var(--hms-border)] bg-slate-50 p-6 text-center">
                                <div>
                                    <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl bg-white text-[var(--hms-text-muted)]">
                                        <FileText aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                                    </div>
                                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">
                                        Aucune réservation sélectionnée
                                    </p>
                                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                                        Sélectionnez une réservation facturable pour afficher l’aperçu.
                                    </p>
                                </div>
                            </div>
                        )}
                    </HmsCard>
                </div>
            </div>

            <HmsCard className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3 text-sm text-[var(--hms-text-muted)]">
                    <FileText aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    {selectedReservation
                        ? `Réservation #${selectedReservation.reservationId} sélectionnée`
                        : "Sélectionnez une réservation facturable"}
                </div>

                <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                    <Link
                        href="/invoices"
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        Annuler
                    </Link>

                    <HmsButton
                        type="button"
                        onClick={() => void handleSubmit()}
                        disabled={isSubmitting || !selectedReservation}
                    >
                        {isSubmitting ? "Génération..." : "Générer la facture"}
                    </HmsButton>
                </div>
            </HmsCard>
        </div>
    );
}

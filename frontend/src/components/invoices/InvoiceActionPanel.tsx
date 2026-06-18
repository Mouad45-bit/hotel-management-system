"use client";

import { useState } from "react";
import {
    ArrowPathIcon,
    CheckCircleIcon,
    CreditCardIcon,
    DocumentCheckIcon,
    NoSymbolIcon,
} from "@heroicons/react/24/outline";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { InvoiceStatusBadge } from "@/components/invoices/InvoiceStatusBadge";
import {
    canCancelInvoice,
    canIssueInvoice,
    canPayInvoice,
    canRefundInvoice,
} from "@/lib/invoiceHelpers";
import {
    cancelInvoice,
    issueInvoice,
    payInvoice,
    refundInvoice,
} from "@/services/invoiceApi";
import {
    cancelInvoiceSchema,
    payInvoiceSchema,
    refundInvoiceSchema,
    type CancelInvoiceFormValues,
    type PayInvoiceFormValues,
    type RefundInvoiceFormValues,
} from "@/schemas/invoice.schema";
import {
    PAYMENT_METHOD_LABELS,
    PAYMENT_METHODS,
    type Invoice,
    type PaymentMethod,
} from "@/types/invoice";

interface InvoiceActionPanelProps {
    invoice: Invoice;
    onInvoiceUpdated: (invoice: Invoice) => void;
}

type PayField = "paymentMethod" | "paymentReference" | "paidAt";
type CancelField = "reason";
type RefundField = "reason" | "paymentReference" | "refundedAt";

function extractActionErrors<TField extends string>(
    issues: { path: PropertyKey[]; message: string }[]
): Partial<Record<TField, string>> {
    const errors: Partial<Record<TField, string>> = {};

    issues.forEach((issue) => {
        const field = issue.path[0];

        if (typeof field === "string") {
            errors[field as TField] = issue.message;
        }
    });

    return errors;
}

export function InvoiceActionPanel({
    invoice,
    onInvoiceUpdated,
}: InvoiceActionPanelProps) {
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    const [payForm, setPayForm] = useState<PayInvoiceFormValues>({
        paymentMethod: "CASH",
        paymentReference: "",
        paidAt: "",
    });

    const [cancelForm, setCancelForm] = useState<CancelInvoiceFormValues>({
        reason: "",
    });

    const [refundForm, setRefundForm] = useState<RefundInvoiceFormValues>({
        reason: "",
        paymentReference: "",
        refundedAt: "",
    });

    const [payErrors, setPayErrors] = useState<
        Partial<Record<PayField, string>>
    >({});

    const [cancelErrors, setCancelErrors] = useState<
        Partial<Record<CancelField, string>>
    >({});

    const [refundErrors, setRefundErrors] = useState<
        Partial<Record<RefundField, string>>
    >({});

    async function runAction(
        callback: () => Promise<Invoice>,
        successMessage: string
    ) {
        setIsSubmitting(true);
        setErrorMessage(null);
        setFeedbackMessage(null);

        try {
            const updatedInvoice = await callback();
            onInvoiceUpdated(updatedInvoice);
            setFeedbackMessage(successMessage);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Action impossible sur cette facture."
            );
        } finally {
            setIsSubmitting(false);
        }
    }

    async function handleIssue() {
        await runAction(
            () => issueInvoice(invoice.id, {}),
            "La facture a été émise avec succès."
        );
    }

    async function handlePay() {
        const validationResult = payInvoiceSchema.safeParse(payForm);

        if (!validationResult.success) {
            setPayErrors(
                extractActionErrors<PayField>(validationResult.error.issues)
            );
            return;
        }

        setPayErrors({});

        await runAction(
            () => payInvoice(invoice.id, validationResult.data),
            "La facture a été marquée comme payée."
        );
    }

    async function handleCancel() {
        const validationResult = cancelInvoiceSchema.safeParse(cancelForm);

        if (!validationResult.success) {
            setCancelErrors(
                extractActionErrors<CancelField>(validationResult.error.issues)
            );
            return;
        }

        setCancelErrors({});

        await runAction(
            () => cancelInvoice(invoice.id, validationResult.data),
            "La facture a été annulée avec succès."
        );
    }

    async function handleRefund() {
        const validationResult = refundInvoiceSchema.safeParse(refundForm);

        if (!validationResult.success) {
            setRefundErrors(
                extractActionErrors<RefundField>(validationResult.error.issues)
            );
            return;
        }

        setRefundErrors({});

        await runAction(
            () => refundInvoice(invoice.id, validationResult.data),
            "La facture a été remboursée avec succès."
        );
    }

    const canDoAnyAction =
        canIssueInvoice(invoice) ||
        canPayInvoice(invoice) ||
        canCancelInvoice(invoice) ||
        canRefundInvoice(invoice);

    return (
        <HmsCard>
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h3 className="text-sm font-semibold text-zinc-950">
                        Actions facture
                    </h3>

                    <p className="mt-1 text-sm text-zinc-500">
                        Actions disponibles selon le statut actuel.
                    </p>
                </div>

                <InvoiceStatusBadge status={invoice.status} />
            </div>

            {feedbackMessage && (
                <div className="mt-4 flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">
                    <CheckCircleIcon className="mt-0.5 h-4 w-4 shrink-0" />
                    {feedbackMessage}
                </div>
            )}

            {errorMessage && (
                <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                    {errorMessage}
                </div>
            )}

            {!canDoAnyAction && (
                <div className="mt-5 rounded-xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-500">
                    Aucune action métier n’est disponible pour ce statut.
                </div>
            )}

            <div className="mt-5 space-y-5">
                {canIssueInvoice(invoice) && (
                    <div className="rounded-2xl border border-zinc-200 p-4">
                        <div className="flex items-start gap-3">
                            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-50 text-blue-700">
                                <DocumentCheckIcon className="h-5 w-5" />
                            </div>

                            <div className="flex-1">
                                <p className="text-sm font-semibold text-zinc-950">
                                    Émettre la facture
                                </p>

                                <p className="mt-1 text-sm text-zinc-500">
                                    La facture passera de Brouillon à Émise.
                                </p>

                                <div className="mt-4">
                                    <HmsButton
                                        type="button"
                                        onClick={() => void handleIssue()}
                                        disabled={isSubmitting}
                                    >
                                        Émettre
                                    </HmsButton>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {canPayInvoice(invoice) && (
                    <div className="rounded-2xl border border-zinc-200 p-4">
                        <div className="flex items-start gap-3">
                            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-50 text-emerald-700">
                                <CreditCardIcon className="h-5 w-5" />
                            </div>

                            <div className="flex-1">
                                <p className="text-sm font-semibold text-zinc-950">
                                    Marquer comme payée
                                </p>

                                <p className="mt-1 text-sm text-zinc-500">
                                    La méthode de paiement est obligatoire.
                                </p>

                                <div className="mt-4 space-y-3">
                                    <div>
                                        <label className="text-xs font-medium text-zinc-600">
                                            Méthode de paiement
                                        </label>

                                        <select
                                            value={payForm.paymentMethod}
                                            onChange={(event) =>
                                                setPayForm((current) => ({
                                                    ...current,
                                                    paymentMethod: event.target
                                                        .value as PaymentMethod,
                                                }))
                                            }
                                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                        >
                                            {PAYMENT_METHODS.map((method) => (
                                                <option key={method} value={method}>
                                                    {PAYMENT_METHOD_LABELS[method]}
                                                </option>
                                            ))}
                                        </select>

                                        {payErrors.paymentMethod && (
                                            <p className="mt-1 text-xs text-red-600">
                                                {payErrors.paymentMethod}
                                            </p>
                                        )}
                                    </div>

                                    <div>
                                        <label className="text-xs font-medium text-zinc-600">
                                            Référence de paiement
                                        </label>

                                        <input
                                            type="text"
                                            value={payForm.paymentReference ?? ""}
                                            onChange={(event) =>
                                                setPayForm((current) => ({
                                                    ...current,
                                                    paymentReference:
                                                        event.target.value,
                                                }))
                                            }
                                            placeholder="CASH-RECEPTION-001"
                                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                        />

                                        {payErrors.paymentReference && (
                                            <p className="mt-1 text-xs text-red-600">
                                                {payErrors.paymentReference}
                                            </p>
                                        )}
                                    </div>

                                    <div>
                                        <label className="text-xs font-medium text-zinc-600">
                                            Date et heure de paiement
                                        </label>

                                        <input
                                            type="datetime-local"
                                            value={payForm.paidAt ?? ""}
                                            onChange={(event) =>
                                                setPayForm((current) => ({
                                                    ...current,
                                                    paidAt: event.target.value,
                                                }))
                                            }
                                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                        />

                                        {payErrors.paidAt && (
                                            <p className="mt-1 text-xs text-red-600">
                                                {payErrors.paidAt}
                                            </p>
                                        )}
                                    </div>

                                    <HmsButton
                                        type="button"
                                        onClick={() => void handlePay()}
                                        disabled={isSubmitting}
                                    >
                                        Confirmer le paiement
                                    </HmsButton>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {canCancelInvoice(invoice) && (
                    <div className="rounded-2xl border border-red-100 bg-red-50/40 p-4">
                        <div className="flex items-start gap-3">
                            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-red-50 text-red-700">
                                <NoSymbolIcon className="h-5 w-5" />
                            </div>

                            <div className="flex-1">
                                <p className="text-sm font-semibold text-zinc-950">
                                    Annuler la facture
                                </p>

                                <p className="mt-1 text-sm text-zinc-500">
                                    Le motif d’annulation est obligatoire.
                                </p>

                                <div className="mt-4 space-y-3">
                                    <div>
                                        <label className="text-xs font-medium text-zinc-600">
                                            Motif d’annulation
                                        </label>

                                        <textarea
                                            value={cancelForm.reason}
                                            onChange={(event) =>
                                                setCancelForm({
                                                    reason: event.target.value,
                                                })
                                            }
                                            rows={3}
                                            placeholder="Erreur de génération de facture"
                                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                        />

                                        {cancelErrors.reason && (
                                            <p className="mt-1 text-xs text-red-600">
                                                {cancelErrors.reason}
                                            </p>
                                        )}
                                    </div>

                                    <HmsButton
                                        type="button"
                                        variant="danger"
                                        onClick={() => void handleCancel()}
                                        disabled={isSubmitting}
                                    >
                                        Annuler la facture
                                    </HmsButton>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {canRefundInvoice(invoice) && (
                    <div className="rounded-2xl border border-purple-100 bg-purple-50/40 p-4">
                        <div className="flex items-start gap-3">
                            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-purple-50 text-purple-700">
                                <ArrowPathIcon className="h-5 w-5" />
                            </div>

                            <div className="flex-1">
                                <p className="text-sm font-semibold text-zinc-950">
                                    Rembourser la facture
                                </p>

                                <p className="mt-1 text-sm text-zinc-500">
                                    Seule une facture payée peut être remboursée.
                                </p>

                                <div className="mt-4 space-y-3">
                                    <div>
                                        <label className="text-xs font-medium text-zinc-600">
                                            Motif de remboursement
                                        </label>

                                        <textarea
                                            value={refundForm.reason}
                                            onChange={(event) =>
                                                setRefundForm((current) => ({
                                                    ...current,
                                                    reason: event.target.value,
                                                }))
                                            }
                                            rows={3}
                                            placeholder="Remboursement demandé par le client"
                                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                        />

                                        {refundErrors.reason && (
                                            <p className="mt-1 text-xs text-red-600">
                                                {refundErrors.reason}
                                            </p>
                                        )}
                                    </div>

                                    <div>
                                        <label className="text-xs font-medium text-zinc-600">
                                            Référence de remboursement
                                        </label>

                                        <input
                                            type="text"
                                            value={
                                                refundForm.paymentReference ?? ""
                                            }
                                            onChange={(event) =>
                                                setRefundForm((current) => ({
                                                    ...current,
                                                    paymentReference:
                                                        event.target.value,
                                                }))
                                            }
                                            placeholder="REFUND-2026-0001"
                                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                        />

                                        {refundErrors.paymentReference && (
                                            <p className="mt-1 text-xs text-red-600">
                                                {refundErrors.paymentReference}
                                            </p>
                                        )}
                                    </div>

                                    <div>
                                        <label className="text-xs font-medium text-zinc-600">
                                            Date et heure de remboursement
                                        </label>

                                        <input
                                            type="datetime-local"
                                            value={refundForm.refundedAt ?? ""}
                                            onChange={(event) =>
                                                setRefundForm((current) => ({
                                                    ...current,
                                                    refundedAt:
                                                        event.target.value,
                                                }))
                                            }
                                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                                        />

                                        {refundErrors.refundedAt && (
                                            <p className="mt-1 text-xs text-red-600">
                                                {refundErrors.refundedAt}
                                            </p>
                                        )}
                                    </div>

                                    <HmsButton
                                        type="button"
                                        variant="secondary"
                                        onClick={() => void handleRefund()}
                                        disabled={isSubmitting}
                                    >
                                        Rembourser
                                    </HmsButton>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </HmsCard>
    );
}

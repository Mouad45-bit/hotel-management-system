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
import { InvoiceCancelModal } from "@/components/invoices/InvoiceCancelModal";
import { InvoiceIssueModal } from "@/components/invoices/InvoiceIssueModal";
import { InvoicePayModal } from "@/components/invoices/InvoicePayModal";
import { InvoiceRefundModal } from "@/components/invoices/InvoiceRefundModal";
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
import type {
    CancelInvoiceRequest,
    Invoice,
    IssueInvoiceRequest,
    PayInvoiceRequest,
    RefundInvoiceRequest,
} from "@/types/invoice";

interface InvoiceActionPanelProps {
    invoice: Invoice;
    onInvoiceUpdated: (invoice: Invoice) => void;
}

type ActiveInvoiceModal = "issue" | "pay" | "cancel" | "refund" | null;

interface ActionCardProps {
    title: string;
    description: string;
    icon: typeof DocumentCheckIcon;
    iconClassName: string;
    buttonLabel: string;
    danger?: boolean;
    disabled?: boolean;
    onClick: () => void;
}

function ActionCard({
    title,
    description,
    icon: Icon,
    iconClassName,
    buttonLabel,
    danger = false,
    disabled = false,
    onClick,
}: ActionCardProps) {
    return (
        <div className="rounded-2xl border border-zinc-200 p-4">
            <div className="flex items-start gap-3">
                <div
                    className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${iconClassName}`}
                >
                    <Icon className="h-5 w-5" />
                </div>

                <div className="flex-1">
                    <p className="text-sm font-semibold text-zinc-950">
                        {title}
                    </p>

                    <p className="mt-1 text-sm leading-6 text-zinc-500">
                        {description}
                    </p>

                    <div className="mt-4">
                        <HmsButton
                            type="button"
                            variant={danger ? "danger" : "secondary"}
                            onClick={onClick}
                            disabled={disabled}
                        >
                            {buttonLabel}
                        </HmsButton>
                    </div>
                </div>
            </div>
        </div>
    );
}

export function InvoiceActionPanel({
    invoice,
    onInvoiceUpdated,
}: InvoiceActionPanelProps) {
    const [activeModal, setActiveModal] = useState<ActiveInvoiceModal>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    function closeModal() {
        if (!isSubmitting) {
            setActiveModal(null);
        }
    }

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
            setActiveModal(null);
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

    async function handleIssue(request: IssueInvoiceRequest) {
        await runAction(
            () => issueInvoice(invoice.id, request),
            "La facture a été émise avec succès."
        );
    }

    async function handlePay(request: PayInvoiceRequest) {
        await runAction(
            () => payInvoice(invoice.id, request),
            "La facture a été marquée comme payée."
        );
    }

    async function handleCancel(request: CancelInvoiceRequest) {
        await runAction(
            () => cancelInvoice(invoice.id, request),
            "La facture a été annulée avec succès."
        );
    }

    async function handleRefund(request: RefundInvoiceRequest) {
        await runAction(
            () => refundInvoice(invoice.id, request),
            "La facture a été remboursée avec succès."
        );
    }

    const issueAllowed = canIssueInvoice(invoice);
    const payAllowed = canPayInvoice(invoice);
    const cancelAllowed = canCancelInvoice(invoice);
    const refundAllowed = canRefundInvoice(invoice);

    const canDoAnyAction =
        issueAllowed || payAllowed || cancelAllowed || refundAllowed;

    return (
        <>
            <HmsCard>
                <div className="flex items-start justify-between gap-4">
                    <div>
                        <h3 className="text-sm font-semibold text-zinc-950">
                            Actions facture
                        </h3>

                        <p className="mt-1 text-sm text-zinc-500">
                            Les actions métier sont confirmées dans des modals
                            pour éviter les changements accidentels.
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

                <div className="mt-5 space-y-4">
                    {issueAllowed && (
                        <ActionCard
                            title="Émettre la facture"
                            description="La facture passera de Brouillon à Émise."
                            icon={DocumentCheckIcon}
                            iconClassName="bg-blue-50 text-blue-700"
                            buttonLabel="Émettre"
                            disabled={isSubmitting}
                            onClick={() => setActiveModal("issue")}
                        />
                    )}

                    {payAllowed && (
                        <ActionCard
                            title="Marquer comme payée"
                            description="La facture passera de Émise à Payée avec une méthode de paiement."
                            icon={CreditCardIcon}
                            iconClassName="bg-emerald-50 text-emerald-700"
                            buttonLabel="Payer"
                            disabled={isSubmitting}
                            onClick={() => setActiveModal("pay")}
                        />
                    )}

                    {cancelAllowed && (
                        <ActionCard
                            title="Annuler la facture"
                            description="La facture sera annulée avec un motif obligatoire."
                            icon={NoSymbolIcon}
                            iconClassName="bg-red-50 text-red-700"
                            buttonLabel="Annuler"
                            danger
                            disabled={isSubmitting}
                            onClick={() => setActiveModal("cancel")}
                        />
                    )}

                    {refundAllowed && (
                        <ActionCard
                            title="Rembourser la facture"
                            description="La facture payée passera au statut Remboursée."
                            icon={ArrowPathIcon}
                            iconClassName="bg-purple-50 text-purple-700"
                            buttonLabel="Rembourser"
                            disabled={isSubmitting}
                            onClick={() => setActiveModal("refund")}
                        />
                    )}
                </div>
            </HmsCard>

            <InvoiceIssueModal
                open={activeModal === "issue"}
                invoice={invoice}
                submitting={isSubmitting}
                onClose={closeModal}
                onConfirm={(request) => void handleIssue(request)}
            />

            <InvoicePayModal
                open={activeModal === "pay"}
                invoice={invoice}
                submitting={isSubmitting}
                onClose={closeModal}
                onConfirm={(request) => void handlePay(request)}
            />

            <InvoiceCancelModal
                open={activeModal === "cancel"}
                invoice={invoice}
                submitting={isSubmitting}
                onClose={closeModal}
                onConfirm={(request) => void handleCancel(request)}
            />

            <InvoiceRefundModal
                open={activeModal === "refund"}
                invoice={invoice}
                submitting={isSubmitting}
                onClose={closeModal}
                onConfirm={(request) => void handleRefund(request)}
            />
        </>
    );
}

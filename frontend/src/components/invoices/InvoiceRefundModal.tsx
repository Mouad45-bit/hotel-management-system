"use client";

import { useEffect, useState } from "react";
import { RotateCcw } from "lucide-react";
import { HmsInput, HmsTextarea } from "@/components/hms/HmsField";
import { InvoiceActionModal } from "@/components/invoices/InvoiceActionModal";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import {
    refundInvoiceSchema,
    type RefundInvoiceFormValues,
} from "@/schemas/invoice.schema";
import { extractFormErrors } from "@/lib/formErrors";
import type {
    Invoice,
    RefundInvoiceRequest,
} from "@/types/invoice";

interface InvoiceRefundModalProps {
    open: boolean;
    invoice: Invoice;
    submitting?: boolean;
    onClose: () => void;
    onConfirm: (request: RefundInvoiceRequest) => void;
}

type RefundField = "reason" | "paymentReference" | "refundedAt";

const DEFAULT_REFUND_FORM: RefundInvoiceFormValues = {
    reason: "",
    paymentReference: "",
    refundedAt: "",
};

export function InvoiceRefundModal({
    open,
    invoice,
    submitting = false,
    onClose,
    onConfirm,
}: InvoiceRefundModalProps) {
    const [form, setForm] =
        useState<RefundInvoiceFormValues>(DEFAULT_REFUND_FORM);

    const [errors, setErrors] = useState<
        Partial<Record<RefundField, string>>
    >({});

    useEffect(() => {
        if (open) {
            const timeoutId = window.setTimeout(() => {
                setForm(DEFAULT_REFUND_FORM);
                setErrors({});
            }, 0);

            return () => window.clearTimeout(timeoutId);
        }
    }, [open]);

    function updateField<K extends keyof RefundInvoiceFormValues>(
        field: K,
        value: RefundInvoiceFormValues[K]
    ) {
        setForm((current) => ({
            ...current,
            [field]: value,
        }));
    }

    function handleConfirm() {
        const validationResult = refundInvoiceSchema.safeParse(form);

        if (!validationResult.success) {
            setErrors(
                extractFormErrors<RefundField>(validationResult.error.issues)
            );
            return;
        }

        setErrors({});
        onConfirm(validationResult.data);
    }

    return (
        <InvoiceActionModal
            open={open}
            title="Rembourser la facture"
            description="Cette action passe une facture payée vers le statut Remboursée."
            icon={RotateCcw}
            iconClassName="bg-purple-50 text-purple-700"
            confirmLabel="Confirmer le remboursement"
            submitting={submitting}
            onClose={onClose}
            onConfirm={handleConfirm}
        >
            <div className="space-y-5">
                <div className="rounded-2xl border border-purple-200 bg-purple-50 p-4">
                    <p className="text-sm font-semibold text-purple-950">
                        Montant à rembourser
                    </p>

                    <InvoiceAmount
                        amount={invoice.totalAmount}
                        variant="strong"
                        className="mt-2 block text-2xl text-purple-950"
                    />

                    <p className="mt-2 text-xs text-purple-700">
                        Facture {invoice.invoiceNumber} · {invoice.clientFullName}
                    </p>
                </div>

                <HmsTextarea
                        id="invoice-refund-reason"
                        label="Motif de remboursement"
                        value={form.reason}
                        onChange={(event) =>
                            updateField("reason", event.target.value)
                        }
                        rows={4}
                        placeholder="Remboursement demandé par le client"
                        error={errors.reason}
                />

                <HmsInput
                        id="invoice-refund-reference"
                        label="Référence de remboursement"
                        type="text"
                        value={form.paymentReference ?? ""}
                        onChange={(event) =>
                            updateField("paymentReference", event.target.value)
                        }
                        placeholder="REFUND-2026-0001"
                        error={errors.paymentReference}
                />

                <HmsInput
                        id="invoice-refunded-at"
                        label="Date et heure de remboursement"
                        type="datetime-local"
                        value={form.refundedAt ?? ""}
                        onChange={(event) =>
                            updateField("refundedAt", event.target.value)
                        }
                        hint="Si ce champ est vide, la date et l’heure courantes seront utilisées."
                        error={errors.refundedAt}
                />
            </div>
        </InvoiceActionModal>
    );
}

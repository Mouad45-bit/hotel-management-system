"use client";

import { useEffect, useState } from "react";
import { ArrowPathIcon } from "@heroicons/react/24/outline";
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
            setForm(DEFAULT_REFUND_FORM);
            setErrors({});
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
            icon={ArrowPathIcon}
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

                <div>
                    <label className="text-xs font-medium text-zinc-600">
                        Motif de remboursement
                    </label>

                    <textarea
                        value={form.reason}
                        onChange={(event) =>
                            updateField("reason", event.target.value)
                        }
                        rows={4}
                        placeholder="Remboursement demandé par le client"
                        className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                    />

                    {errors.reason && (
                        <p className="mt-1 text-xs text-red-600">
                            {errors.reason}
                        </p>
                    )}
                </div>

                <div>
                    <label className="text-xs font-medium text-zinc-600">
                        Référence de remboursement
                    </label>

                    <input
                        type="text"
                        value={form.paymentReference ?? ""}
                        onChange={(event) =>
                            updateField("paymentReference", event.target.value)
                        }
                        placeholder="REFUND-2026-0001"
                        className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                    />

                    {errors.paymentReference && (
                        <p className="mt-1 text-xs text-red-600">
                            {errors.paymentReference}
                        </p>
                    )}
                </div>

                <div>
                    <label className="text-xs font-medium text-zinc-600">
                        Date et heure de remboursement
                    </label>

                    <input
                        type="datetime-local"
                        value={form.refundedAt ?? ""}
                        onChange={(event) =>
                            updateField("refundedAt", event.target.value)
                        }
                        className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                    />

                    <p className="mt-1 text-xs text-zinc-500">
                        Si ce champ est vide, la date et l’heure courantes seront utilisées.
                    </p>

                    {errors.refundedAt && (
                        <p className="mt-1 text-xs text-red-600">
                            {errors.refundedAt}
                        </p>
                    )}
                </div>
            </div>
        </InvoiceActionModal>
    );
}

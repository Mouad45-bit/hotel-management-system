"use client";

import { useEffect, useState } from "react";
import { NoSymbolIcon } from "@heroicons/react/24/outline";
import { InvoiceActionModal } from "@/components/invoices/InvoiceActionModal";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import {
    cancelInvoiceSchema,
    type CancelInvoiceFormValues,
} from "@/schemas/invoice.schema";
import { extractFormErrors } from "@/lib/formErrors";
import type {
    CancelInvoiceRequest,
    Invoice,
} from "@/types/invoice";

interface InvoiceCancelModalProps {
    open: boolean;
    invoice: Invoice;
    submitting?: boolean;
    onClose: () => void;
    onConfirm: (request: CancelInvoiceRequest) => void;
}

type CancelField = "reason";

const DEFAULT_CANCEL_FORM: CancelInvoiceFormValues = {
    reason: "",
};

export function InvoiceCancelModal({
    open,
    invoice,
    submitting = false,
    onClose,
    onConfirm,
}: InvoiceCancelModalProps) {
    const [form, setForm] =
        useState<CancelInvoiceFormValues>(DEFAULT_CANCEL_FORM);

    const [errors, setErrors] = useState<
        Partial<Record<CancelField, string>>
    >({});

    useEffect(() => {
        if (open) {
            setForm(DEFAULT_CANCEL_FORM);
            setErrors({});
        }
    }, [open]);

    function handleConfirm() {
        const validationResult = cancelInvoiceSchema.safeParse(form);

        if (!validationResult.success) {
            setErrors(
                extractFormErrors<CancelField>(validationResult.error.issues)
            );
            return;
        }

        setErrors({});
        onConfirm(validationResult.data);
    }

    return (
        <InvoiceActionModal
            open={open}
            title="Annuler la facture"
            description="Cette action conserve la facture dans l’historique, mais bloque son cycle de paiement."
            icon={NoSymbolIcon}
            iconClassName="bg-red-50 text-red-700"
            confirmLabel="Confirmer l’annulation"
            submitting={submitting}
            danger
            onClose={onClose}
            onConfirm={handleConfirm}
        >
            <div className="space-y-5">
                <div className="rounded-2xl border border-red-200 bg-red-50 p-4">
                    <p className="text-sm font-semibold text-red-950">
                        Action sensible
                    </p>

                    <p className="mt-1 text-sm text-red-700">
                        Une facture annulée ne pourra plus être payée.
                    </p>

                    <div className="mt-3 flex items-center justify-between text-sm">
                        <span className="text-red-700">
                            Montant concerné
                        </span>

                        <InvoiceAmount
                            amount={invoice.totalAmount}
                            variant="danger"
                            className="text-sm"
                        />
                    </div>
                </div>

                <div>
                    <label className="text-xs font-medium text-zinc-600">
                        Motif d’annulation
                    </label>

                    <textarea
                        value={form.reason}
                        onChange={(event) =>
                            setForm({
                                reason: event.target.value,
                            })
                        }
                        rows={4}
                        placeholder="Erreur de génération de facture"
                        className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                    />

                    {errors.reason && (
                        <p className="mt-1 text-xs text-red-600">
                            {errors.reason}
                        </p>
                    )}
                </div>
            </div>
        </InvoiceActionModal>
    );
}

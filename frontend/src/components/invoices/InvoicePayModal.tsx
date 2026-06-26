"use client";

import { useEffect, useState } from "react";
import { CreditCard } from "lucide-react";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { InvoiceActionModal } from "@/components/invoices/InvoiceActionModal";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import {
    payInvoiceSchema,
    type PayInvoiceFormValues,
} from "@/schemas/invoice.schema";
import { extractFormErrors } from "@/lib/formErrors";
import {
    PAYMENT_METHOD_LABELS,
    PAYMENT_METHODS,
    type Invoice,
    type PayInvoiceRequest,
    type PaymentMethod,
} from "@/types/invoice";

interface InvoicePayModalProps {
    open: boolean;
    invoice: Invoice;
    submitting?: boolean;
    onClose: () => void;
    onConfirm: (request: PayInvoiceRequest) => void;
}

type PayField = "paymentMethod" | "paymentReference" | "paidAt";

const DEFAULT_PAY_FORM: PayInvoiceFormValues = {
    paymentMethod: "CASH",
    paymentReference: "",
    paidAt: "",
};

export function InvoicePayModal({
    open,
    invoice,
    submitting = false,
    onClose,
    onConfirm,
}: InvoicePayModalProps) {
    const [form, setForm] =
        useState<PayInvoiceFormValues>(DEFAULT_PAY_FORM);

    const [errors, setErrors] = useState<Partial<Record<PayField, string>>>({});

    useEffect(() => {
        if (open) {
            const timeoutId = window.setTimeout(() => {
                setForm(DEFAULT_PAY_FORM);
                setErrors({});
            }, 0);

            return () => window.clearTimeout(timeoutId);
        }
    }, [open]);

    function updateField<K extends keyof PayInvoiceFormValues>(
        field: K,
        value: PayInvoiceFormValues[K]
    ) {
        setForm((current) => ({
            ...current,
            [field]: value,
        }));
    }

    function handleConfirm() {
        const validationResult = payInvoiceSchema.safeParse(form);

        if (!validationResult.success) {
            setErrors(extractFormErrors<PayField>(validationResult.error.issues));
            return;
        }

        setErrors({});
        onConfirm(validationResult.data);
    }

    return (
        <InvoiceActionModal
            open={open}
            title="Marquer la facture comme payée"
            description="Cette action passe la facture de Émise à Payée. La méthode de paiement est obligatoire."
            icon={CreditCard}
            iconClassName="bg-emerald-50 text-emerald-700"
            confirmLabel="Confirmer le paiement"
            submitting={submitting}
            onClose={onClose}
            onConfirm={handleConfirm}
        >
            <div className="space-y-5">
                <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
                    <p className="text-sm font-semibold text-emerald-950">
                        Montant à encaisser
                    </p>

                    <InvoiceAmount
                        amount={invoice.totalAmount}
                        variant="success"
                        className="mt-2 block text-2xl"
                    />

                    <p className="mt-2 text-xs text-emerald-700">
                        Facture {invoice.invoiceNumber} · {invoice.clientFullName}
                    </p>
                </div>

                <HmsSelect
                        id="invoice-payment-method"
                        label="Méthode de paiement"
                        value={form.paymentMethod}
                        onChange={(event) =>
                            updateField(
                                "paymentMethod",
                                event.target.value as PaymentMethod
                            )
                        }
                        error={errors.paymentMethod}
                >
                        {PAYMENT_METHODS.map((method) => (
                            <option key={method} value={method}>
                                {PAYMENT_METHOD_LABELS[method]}
                            </option>
                        ))}
                </HmsSelect>

                <HmsInput
                        id="invoice-payment-reference"
                        label="Référence de paiement"
                        type="text"
                        value={form.paymentReference ?? ""}
                        onChange={(event) =>
                            updateField("paymentReference", event.target.value)
                        }
                        placeholder="CASH-RECEPTION-001"
                        error={errors.paymentReference}
                />

                <HmsInput
                        id="invoice-paid-at"
                        label="Date et heure de paiement"
                        type="datetime-local"
                        value={form.paidAt ?? ""}
                        onChange={(event) =>
                            updateField("paidAt", event.target.value)
                        }
                        hint="Si ce champ est vide, la date et l’heure courantes seront utilisées."
                        error={errors.paidAt}
                />
            </div>
        </InvoiceActionModal>
    );
}

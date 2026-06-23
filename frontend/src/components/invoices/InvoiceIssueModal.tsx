"use client";

import { useEffect, useState } from "react";
import { DocumentCheckIcon } from "@heroicons/react/24/outline";
import { InvoiceActionModal } from "@/components/invoices/InvoiceActionModal";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { issueInvoiceSchema } from "@/schemas/invoice.schema";
import { extractFormErrors } from "@/lib/formErrors";
import type {
    Invoice,
    IssueInvoiceRequest,
} from "@/types/invoice";

interface InvoiceIssueModalProps {
    open: boolean;
    invoice: Invoice;
    submitting?: boolean;
    onClose: () => void;
    onConfirm: (request: IssueInvoiceRequest) => void;
}

type IssueField = "issueDate";

export function InvoiceIssueModal({
    open,
    invoice,
    submitting = false,
    onClose,
    onConfirm,
}: InvoiceIssueModalProps) {
    const [issueDate, setIssueDate] = useState("");
    const [errors, setErrors] = useState<Partial<Record<IssueField, string>>>({});

    useEffect(() => {
        if (open) {
            const timeoutId = window.setTimeout(() => {
                setIssueDate("");
                setErrors({});
            }, 0);

            return () => window.clearTimeout(timeoutId);
        }
    }, [open]);

    function handleConfirm() {
        const validationResult = issueInvoiceSchema.safeParse({
            issueDate,
        });

        if (!validationResult.success) {
            setErrors(
                extractFormErrors<IssueField>(validationResult.error.issues)
            );
            return;
        }

        setErrors({});
        onConfirm(validationResult.data);
    }

    return (
        <InvoiceActionModal
            open={open}
            title="Émettre la facture"
            description="Cette action valide la facture brouillon et la rend prête à être payée."
            icon={DocumentCheckIcon}
            iconClassName="bg-blue-50 text-blue-700"
            confirmLabel="Émettre la facture"
            submitting={submitting}
            onClose={onClose}
            onConfirm={handleConfirm}
        >
            <div className="space-y-5">
                <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                    <p className="text-sm font-semibold text-zinc-950">
                        {invoice.invoiceNumber}
                    </p>

                    <p className="mt-1 text-sm text-zinc-500">
                        Client : {invoice.clientFullName}
                    </p>

                    <div className="mt-3 flex items-center justify-between text-sm">
                        <span className="text-zinc-500">Total TTC</span>

                        <InvoiceAmount
                            amount={invoice.totalAmount}
                            variant="strong"
                            className="text-sm"
                        />
                    </div>
                </div>

                <div>
                    <label className="text-xs font-medium text-zinc-600">
                        Date d’émission
                    </label>

                    <input
                        type="date"
                        value={issueDate}
                        onChange={(event) => setIssueDate(event.target.value)}
                        className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                    />

                    <p className="mt-1 text-xs text-zinc-500">
                        Si ce champ est vide, la date du jour sera utilisée.
                    </p>

                    {errors.issueDate && (
                        <p className="mt-1 text-xs text-red-600">
                            {errors.issueDate}
                        </p>
                    )}
                </div>
            </div>
        </InvoiceActionModal>
    );
}

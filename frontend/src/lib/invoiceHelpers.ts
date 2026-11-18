import {
    INVOICE_LINE_TYPE_LABELS,
    INVOICE_STATUS_LABELS,
    PAYMENT_METHOD_LABELS,
    type Invoice,
    type InvoiceLineType,
    type InvoiceStatus,
    type PaymentMethod,
} from "@/types/invoice";

export type InvoiceAction =
    | "view"
    | "issue"
    | "pay"
    | "cancel"
    | "refund"
    | "print";

export function formatInvoiceAmount(
    amount: number,
    currency = "MAD",
    locale = "fr-MA"
): string {
    return new Intl.NumberFormat(locale, {
        style: "currency",
        currency,
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
    }).format(amount);
}

export function formatInvoiceDate(
    value?: string | null,
    options: { withTime?: boolean } = {}
): string {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    return new Intl.DateTimeFormat("fr-FR", {
        dateStyle: "medium",
        ...(options.withTime ? { timeStyle: "short" } : {}),
    }).format(date);
}

export function formatInvoiceDateTime(value?: string | null): string {
    return formatInvoiceDate(value, { withTime: true });
}

export function getInvoiceStatusDisplayLabel(status: InvoiceStatus): string {
    return INVOICE_STATUS_LABELS[status];
}

export function getPaymentMethodDisplayLabel(
    paymentMethod?: PaymentMethod | null
): string {
    if (!paymentMethod) {
        return "Non renseigné";
    }

    return PAYMENT_METHOD_LABELS[paymentMethod];
}

export function getInvoiceLineTypeDisplayLabel(
    type: InvoiceLineType
): string {
    return INVOICE_LINE_TYPE_LABELS[type];
}

export function formatInvoicePeriod(
    invoice: Pick<Invoice, "checkInDate" | "checkOutDate" | "nights">
): string {
    const nightLabel = invoice.nights > 1 ? "nuits" : "nuit";

    return `${formatInvoiceDate(invoice.checkInDate)} → ${formatInvoiceDate(
        invoice.checkOutDate
    )} · ${invoice.nights} ${nightLabel}`;
}

export function formatInvoiceRoom(
    invoice: Pick<Invoice, "roomNumber">
): string {
    return `Chambre ${invoice.roomNumber}`;
}

export function canIssueInvoice(invoice: Invoice): boolean {
    return invoice.status === "DRAFT";
}

export function canPayInvoice(invoice: Invoice): boolean {
    return invoice.status === "ISSUED";
}

export function canCancelInvoice(invoice: Invoice): boolean {
    return invoice.status === "DRAFT" || invoice.status === "ISSUED";
}

export function canRefundInvoice(invoice: Invoice): boolean {
    return invoice.status === "PAID";
}

export function canPrintInvoice(invoice: Invoice): boolean {
    return invoice.status !== "DRAFT";
}

export function isFinalInvoiceStatus(status: InvoiceStatus): boolean {
    return status === "CANCELLED" || status === "REFUNDED";
}

export function isPaidInvoice(invoice: Invoice): boolean {
    return invoice.status === "PAID";
}

export function getAvailableInvoiceActions(invoice: Invoice): InvoiceAction[] {
    const actions: InvoiceAction[] = ["view"];

    if (canIssueInvoice(invoice)) {
        actions.push("issue");
    }

    if (canPayInvoice(invoice)) {
        actions.push("pay");
    }

    if (canCancelInvoice(invoice)) {
        actions.push("cancel");
    }

    if (canRefundInvoice(invoice)) {
        actions.push("refund");
    }

    if (canPrintInvoice(invoice)) {
        actions.push("print");
    }

    return actions;
}

export function getInvoiceActionLabel(action: InvoiceAction): string {
    const labels: Record<InvoiceAction, string> = {
        view: "Voir",
        issue: "Émettre",
        pay: "Payer",
        cancel: "Annuler",
        refund: "Rembourser",
        print: "Imprimer",
    };

    return labels[action];
}

export const INVOICE_STATUSES = [
    "DRAFT",
    "ISSUED",
    "PAID",
    "CANCELLED",
    "REFUNDED",
] as const;

export type InvoiceStatus = (typeof INVOICE_STATUSES)[number];

export const PAYMENT_METHODS = [
    "CASH",
    "CARD",
    "BANK_TRANSFER",
    "OTHER",
] as const;

export type PaymentMethod = (typeof PAYMENT_METHODS)[number];

export const INVOICE_LINE_TYPES = [
    "ROOM_STAY",
    "EXTRA_SERVICE",
    "DISCOUNT",
] as const;

export type InvoiceLineType = (typeof INVOICE_LINE_TYPES)[number];

export type InvoiceStatusFilter = InvoiceStatus | "ALL";

export type InvoiceStatusTone =
    | "neutral"
    | "info"
    | "success"
    | "danger"
    | "purple";

export interface InvoiceLine {
    id: number;
    type: InvoiceLineType;
    description: string;
    quantity: number;
    unitPrice: number;
    lineTotal: number;
}

export interface Invoice {
    id: number;
    invoiceNumber: string;

    reservationId: number;
    clientId: number;
    clientFullName: string;

    roomId: number;
    roomNumber: string;

    checkInDate: string;
    checkOutDate: string;
    nights: number;
    pricePerNight: number;

    subtotalAmount: number;
    taxRate: number;
    taxAmount: number;
    totalAmount: number;

    status: InvoiceStatus;

    paymentMethod?: PaymentMethod | null;
    paymentReference?: string | null;

    notes?: string | null;
    cancellationReason?: string | null;
    refundReason?: string | null;

    issuedAt?: string | null;
    paidAt?: string | null;
    cancelledAt?: string | null;
    refundedAt?: string | null;

    createdAt: string;
    updatedAt: string;

    lines: InvoiceLine[];
}

export interface GenerateInvoiceFromReservationRequest {
    taxRate: number;
    notes?: string;
}

export interface IssueInvoiceRequest {
    issueDate?: string;
}

export interface PayInvoiceRequest {
    paymentMethod: PaymentMethod;
    paymentReference?: string;
    paidAt?: string;
}

export interface CancelInvoiceRequest {
    reason: string;
}

export interface RefundInvoiceRequest {
    reason: string;
    paymentReference?: string;
    refundedAt?: string;
}

export interface InvoiceSearchParams {
    number?: string;
    status?: InvoiceStatus;
    clientId?: number;
    reservationId?: number;
    from?: string;
    to?: string;
    page?: number;
    size?: number;
    sort?: string;
}

export interface InvoiceFiltersState {
    number: string;
    status: InvoiceStatusFilter;
    clientId: string;
    reservationId: string;
    from: string;
    to: string;
}

export interface InvoiceStats {
    total: number;
    draft: number;
    issued: number;
    paid: number;
    cancelled: number;
    refunded: number;
    totalRevenue: number;
    pendingAmount: number;
    refundedAmount: number;
}

export interface PageResponse<T> {
    content: T[];
    page: number;
    size: number;
    totalElements: number;
    totalPages: number;
    last: boolean;
}

export type InvoiceReservationStatus =
    | "CREATED"
    | "CONFIRMED"
    | "CHECKED_IN"
    | "CHECKED_OUT"
    | "CANCELLED"
    | "NO_SHOW";

export interface ReservationInvoiceSource {
    reservationId: number;
    reservationStatus: InvoiceReservationStatus;

    clientId: number;
    clientFullName: string;

    roomId: number;
    roomNumber: string;

    checkInDate: string;
    checkOutDate: string;
    nights: number;
    pricePerNight: number;

    hasActiveInvoice: boolean;
}

export const INVOICE_STATUS_LABELS: Record<InvoiceStatus, string> = {
    DRAFT: "Brouillon",
    ISSUED: "Émise",
    PAID: "Payée",
    CANCELLED: "Annulée",
    REFUNDED: "Remboursée",
};

export const INVOICE_STATUS_FILTER_LABELS: Record<InvoiceStatusFilter, string> = {
    ALL: "Tous les statuts",
    DRAFT: "Brouillon",
    ISSUED: "Émise",
    PAID: "Payée",
    CANCELLED: "Annulée",
    REFUNDED: "Remboursée",
};

export const INVOICE_STATUS_TONES: Record<InvoiceStatus, InvoiceStatusTone> = {
    DRAFT: "neutral",
    ISSUED: "info",
    PAID: "success",
    CANCELLED: "danger",
    REFUNDED: "purple",
};

export const INVOICE_STATUS_BADGE_CLASSES: Record<InvoiceStatus, string> = {
    DRAFT: "bg-zinc-100 text-zinc-700 ring-zinc-200",
    ISSUED: "bg-blue-50 text-blue-700 ring-blue-200",
    PAID: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    CANCELLED: "bg-red-50 text-red-700 ring-red-200",
    REFUNDED: "bg-purple-50 text-purple-700 ring-purple-200",
};

export const PAYMENT_METHOD_LABELS: Record<PaymentMethod, string> = {
    CASH: "Espèces",
    CARD: "Carte bancaire",
    BANK_TRANSFER: "Virement bancaire",
    OTHER: "Autre",
};

export const INVOICE_LINE_TYPE_LABELS: Record<InvoiceLineType, string> = {
    ROOM_STAY: "Séjour",
    EXTRA_SERVICE: "Service supplémentaire",
    DISCOUNT: "Remise",
};

export const DEFAULT_INVOICE_FILTERS: InvoiceFiltersState = {
    number: "",
    status: "ALL",
    clientId: "",
    reservationId: "",
    from: "",
    to: "",
};

export function getInvoiceStatusLabel(status: InvoiceStatus): string {
    return INVOICE_STATUS_LABELS[status];
}

export function getPaymentMethodLabel(paymentMethod: PaymentMethod): string {
    return PAYMENT_METHOD_LABELS[paymentMethod];
}

export function isInvoicePayable(invoice: Invoice): boolean {
    return invoice.status === "ISSUED";
}

export function isInvoiceCancellable(invoice: Invoice): boolean {
    return invoice.status === "DRAFT" || invoice.status === "ISSUED";
}

export function isInvoiceRefundable(invoice: Invoice): boolean {
    return invoice.status === "PAID";
}

export function isInvoiceReadonly(invoice: Invoice): boolean {
    return invoice.status === "PAID"
        || invoice.status === "CANCELLED"
        || invoice.status === "REFUNDED";
}

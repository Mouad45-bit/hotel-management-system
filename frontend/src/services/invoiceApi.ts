import { apiFetch } from "@/lib/api";
import {
    mockInvoices,
    mockReservationInvoiceSources,
} from "@/mocks/invoices";
import type {
    CancelInvoiceRequest,
    GenerateInvoiceFromReservationRequest,
    Invoice,
    InvoiceSearchParams,
    InvoiceStats,
    InvoiceStatus,
    IssueInvoiceRequest,
    PageResponse,
    PayInvoiceRequest,
    RefundInvoiceRequest,
    ReservationInvoiceSource,
} from "@/types/invoice";

const USE_MOCK_API = process.env.NEXT_PUBLIC_USE_INVOICE_MOCKS !== "false";

const MOCK_DELAY_MS = 150;

let invoiceStore: Invoice[] = mockInvoices.map(clone);
let reservationInvoiceSourceStore: ReservationInvoiceSource[] =
    mockReservationInvoiceSources.map(clone);

function clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value)) as T;
}

function mockResponse<T>(value: T): Promise<T> {
    return new Promise((resolve) => {
        setTimeout(() => resolve(clone(value)), MOCK_DELAY_MS);
    });
}

function nowIsoDateTime(): string {
    return new Date().toISOString().slice(0, 19);
}

function roundMoney(value: number): number {
    return Math.round(value * 100) / 100;
}

function buildQueryString(params: InvoiceSearchParams): string {
    const searchParams = new URLSearchParams();

    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== "") {
            searchParams.set(key, String(value));
        }
    });

    const queryString = searchParams.toString();

    return queryString ? `?${queryString}` : "";
}

function isActiveInvoiceStatus(status: InvoiceStatus): boolean {
    return status === "DRAFT" || status === "ISSUED" || status === "PAID";
}

function getNextInvoiceId(): number {
    return Math.max(0, ...invoiceStore.map((invoice) => invoice.id)) + 1;
}

function getNextInvoiceLineId(): number {
    return (
        Math.max(
            0,
            ...invoiceStore.flatMap((invoice) =>
                invoice.lines.map((line) => line.id)
            )
        ) + 1
    );
}

function generateNextInvoiceNumber(): string {
    const nextId = getNextInvoiceId();

    return `INV-2026-${String(nextId).padStart(6, "0")}`;
}

function getInvoiceOrThrow(id: number): Invoice {
    const invoice = invoiceStore.find((item) => item.id === id);

    if (!invoice) {
        throw new Error(`Facture introuvable avec l'identifiant ${id}.`);
    }

    return invoice;
}

function updateInvoice(
    id: number,
    updater: (invoice: Invoice) => Invoice
): Invoice {
    const currentInvoice = getInvoiceOrThrow(id);
    const updatedInvoice = {
        ...updater(currentInvoice),
        updatedAt: nowIsoDateTime(),
    };

    invoiceStore = invoiceStore.map((invoice) =>
        invoice.id === id ? updatedInvoice : invoice
    );

    return updatedInvoice;
}

function filterInvoices(params: InvoiceSearchParams): Invoice[] {
    return invoiceStore.filter((invoice) => {
        const matchesNumber =
            !params.number ||
            invoice.invoiceNumber
                .toLowerCase()
                .includes(params.number.trim().toLowerCase());

        const matchesStatus = !params.status || invoice.status === params.status;

        const matchesClient =
            params.clientId === undefined || invoice.clientId === params.clientId;

        const matchesReservation =
            params.reservationId === undefined ||
            invoice.reservationId === params.reservationId;

        const invoiceDate = invoice.createdAt.slice(0, 10);

        const matchesFrom = !params.from || invoiceDate >= params.from;
        const matchesTo = !params.to || invoiceDate <= params.to;

        return (
            matchesNumber &&
            matchesStatus &&
            matchesClient &&
            matchesReservation &&
            matchesFrom &&
            matchesTo
        );
    });
}

function sortInvoices(invoices: Invoice[], sort?: string): Invoice[] {
    const [field = "createdAt", direction = "desc"] = (
        sort || "createdAt,desc"
    ).split(",");

    const sortedInvoices = [...invoices].sort((first, second) => {
        const firstValue = first[field as keyof Invoice];
        const secondValue = second[field as keyof Invoice];

        if (
            typeof firstValue === "number" &&
            typeof secondValue === "number"
        ) {
            return firstValue - secondValue;
        }

        return String(firstValue ?? "").localeCompare(String(secondValue ?? ""));
    });

    return direction === "desc" ? sortedInvoices.reverse() : sortedInvoices;
}

function createPageResponse<T>(
    content: T[],
    page: number,
    size: number
): PageResponse<T> {
    const startIndex = page * size;
    const paginatedContent = content.slice(startIndex, startIndex + size);

    return {
        content: paginatedContent,
        page,
        size,
        totalElements: content.length,
        totalPages: Math.ceil(content.length / size),
        last: startIndex + size >= content.length,
    };
}

function calculateInvoiceStats(invoices: Invoice[]): InvoiceStats {
    return {
        total: invoices.length,

        draft: invoices.filter((invoice) => invoice.status === "DRAFT").length,

        issued: invoices.filter((invoice) => invoice.status === "ISSUED").length,

        paid: invoices.filter((invoice) => invoice.status === "PAID").length,

        cancelled: invoices.filter((invoice) => invoice.status === "CANCELLED")
            .length,

        refunded: invoices.filter((invoice) => invoice.status === "REFUNDED")
            .length,

        totalRevenue: invoices
            .filter((invoice) => invoice.status === "PAID")
            .reduce((sum, invoice) => sum + invoice.totalAmount, 0),

        pendingAmount: invoices
            .filter((invoice) => invoice.status === "ISSUED")
            .reduce((sum, invoice) => sum + invoice.totalAmount, 0),

        refundedAmount: invoices
            .filter((invoice) => invoice.status === "REFUNDED")
            .reduce((sum, invoice) => sum + invoice.totalAmount, 0),
    };
}

export async function getInvoices(
    params: InvoiceSearchParams = {}
): Promise<PageResponse<Invoice>> {
    if (!USE_MOCK_API) {
        const queryString = buildQueryString(params);

        return apiFetch<PageResponse<Invoice>>(`/api/invoices${queryString}`);
    }

    const page = params.page ?? 0;
    const size = params.size ?? 20;

    const filteredInvoices = filterInvoices(params);
    const sortedInvoices = sortInvoices(filteredInvoices, params.sort);

    return mockResponse(createPageResponse(sortedInvoices, page, size));
}

export async function getInvoiceById(id: number): Promise<Invoice> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice>(`/api/invoices/${id}`);
    }

    return mockResponse(getInvoiceOrThrow(id));
}

export async function getInvoiceByNumber(
    invoiceNumber: string
): Promise<Invoice> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice>(`/api/invoices/number/${invoiceNumber}`);
    }

    const invoice = invoiceStore.find(
        (item) => item.invoiceNumber === invoiceNumber
    );

    if (!invoice) {
        throw new Error(`Facture introuvable avec le numéro ${invoiceNumber}.`);
    }

    return mockResponse(invoice);
}

export async function getInvoicesByClientId(
    clientId: number
): Promise<Invoice[]> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice[]>(`/api/invoices/client/${clientId}`);
    }

    const invoices = invoiceStore.filter((invoice) => invoice.clientId === clientId);

    return mockResponse(invoices);
}

export async function getInvoiceByReservationId(
    reservationId: number
): Promise<Invoice> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice>(`/api/invoices/reservation/${reservationId}`);
    }

    const invoice = invoiceStore.find(
        (item) => item.reservationId === reservationId
    );

    if (!invoice) {
        throw new Error(
            `Facture introuvable pour la réservation ${reservationId}.`
        );
    }

    return mockResponse(invoice);
}

export async function getInvoiceStats(): Promise<InvoiceStats> {
    if (!USE_MOCK_API) {
        const invoicesPage = await getInvoices({
            page: 0,
            size: 1000,
            sort: "createdAt,desc",
        });

        return calculateInvoiceStats(invoicesPage.content);
    }

    return mockResponse(calculateInvoiceStats(invoiceStore));
}

export async function getReservationInvoiceSources(): Promise<
    ReservationInvoiceSource[]
> {
    if (!USE_MOCK_API) {
        return [];
    }

    return mockResponse(reservationInvoiceSourceStore);
}

export async function getReservationInvoiceSourceById(
    reservationId: number
): Promise<ReservationInvoiceSource> {
    const reservation = reservationInvoiceSourceStore.find(
        (item) => item.reservationId === reservationId
    );

    if (!reservation) {
        throw new Error(
            `Réservation introuvable avec l'identifiant ${reservationId}.`
        );
    }

    return mockResponse(reservation);
}

export async function generateInvoiceFromReservation(
    reservationId: number,
    request: GenerateInvoiceFromReservationRequest
): Promise<Invoice> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice>(`/api/invoices/reservation/${reservationId}`, {
            method: "POST",
            body: JSON.stringify(request),
        });
    }

    const reservation = reservationInvoiceSourceStore.find(
        (item) => item.reservationId === reservationId
    );

    if (!reservation) {
        throw new Error(
            `Réservation introuvable avec l'identifiant ${reservationId}.`
        );
    }

    if (reservation.reservationStatus !== "CHECKED_OUT") {
        throw new Error(
            "La facture peut être générée uniquement pour une réservation terminée."
        );
    }

    const hasActiveInvoice = invoiceStore.some(
        (invoice) =>
            invoice.reservationId === reservationId &&
            isActiveInvoiceStatus(invoice.status)
    );

    if (hasActiveInvoice) {
        throw new Error(
            `Une facture active existe déjà pour la réservation ${reservationId}.`
        );
    }

    const now = nowIsoDateTime();

    const invoiceId = getNextInvoiceId();
    const invoiceLineId = getNextInvoiceLineId();

    const subtotalAmount = roundMoney(
        reservation.nights * reservation.pricePerNight
    );

    const taxAmount = roundMoney((subtotalAmount * request.taxRate) / 100);

    const totalAmount = roundMoney(subtotalAmount + taxAmount);

    const invoice: Invoice = {
        id: invoiceId,
        invoiceNumber: generateNextInvoiceNumber(),

        reservationId: reservation.reservationId,
        clientId: reservation.clientId,
        clientFullName: reservation.clientFullName,

        roomId: reservation.roomId,
        roomNumber: reservation.roomNumber,

        checkInDate: reservation.checkInDate,
        checkOutDate: reservation.checkOutDate,
        nights: reservation.nights,
        pricePerNight: reservation.pricePerNight,

        subtotalAmount,
        taxRate: request.taxRate,
        taxAmount,
        totalAmount,

        status: "DRAFT",

        paymentMethod: null,
        paymentReference: null,

        notes: request.notes ?? null,
        cancellationReason: null,
        refundReason: null,

        issuedAt: null,
        paidAt: null,
        cancelledAt: null,
        refundedAt: null,

        createdAt: now,
        updatedAt: now,

        lines: [
            {
                id: invoiceLineId,
                type: "ROOM_STAY",
                description: `Séjour chambre ${reservation.roomNumber} - ${reservation.nights} nuit(s)`,
                quantity: reservation.nights,
                unitPrice: reservation.pricePerNight,
                lineTotal: subtotalAmount,
            },
        ],
    };

    invoiceStore = [invoice, ...invoiceStore];

    reservationInvoiceSourceStore = reservationInvoiceSourceStore.map((item) =>
        item.reservationId === reservationId
            ? { ...item, hasActiveInvoice: true }
            : item
    );

    return mockResponse(invoice);
}

export async function issueInvoice(
    id: number,
    request: IssueInvoiceRequest = {}
): Promise<Invoice> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice>(`/api/invoices/${id}/issue`, {
            method: "PATCH",
            body: JSON.stringify(request),
        });
    }

    const updatedInvoice = updateInvoice(id, (invoice) => {
        if (invoice.status !== "DRAFT") {
            throw new Error("Seule une facture brouillon peut être émise.");
        }

        const issuedAt = request.issueDate
            ? `${request.issueDate}T00:00:00`
            : nowIsoDateTime();

        return {
            ...invoice,
            status: "ISSUED",
            issuedAt,
        };
    });

    return mockResponse(updatedInvoice);
}

export async function payInvoice(
    id: number,
    request: PayInvoiceRequest
): Promise<Invoice> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice>(`/api/invoices/${id}/pay`, {
            method: "PATCH",
            body: JSON.stringify(request),
        });
    }

    const updatedInvoice = updateInvoice(id, (invoice) => {
        if (invoice.status !== "ISSUED") {
            throw new Error("Seule une facture émise peut être payée.");
        }

        return {
            ...invoice,
            status: "PAID",
            paymentMethod: request.paymentMethod,
            paymentReference: request.paymentReference ?? null,
            paidAt: request.paidAt ?? nowIsoDateTime(),
        };
    });

    return mockResponse(updatedInvoice);
}

export async function cancelInvoice(
    id: number,
    request: CancelInvoiceRequest
): Promise<Invoice> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice>(`/api/invoices/${id}/cancel`, {
            method: "PATCH",
            body: JSON.stringify(request),
        });
    }

    const updatedInvoice = updateInvoice(id, (invoice) => {
        if (invoice.status !== "DRAFT" && invoice.status !== "ISSUED") {
            throw new Error(
                "Seule une facture brouillon ou émise peut être annulée."
            );
        }

        return {
            ...invoice,
            status: "CANCELLED",
            cancellationReason: request.reason,
            cancelledAt: nowIsoDateTime(),
        };
    });

    return mockResponse(updatedInvoice);
}

export async function refundInvoice(
    id: number,
    request: RefundInvoiceRequest
): Promise<Invoice> {
    if (!USE_MOCK_API) {
        return apiFetch<Invoice>(`/api/invoices/${id}/refund`, {
            method: "PATCH",
            body: JSON.stringify(request),
        });
    }

    const updatedInvoice = updateInvoice(id, (invoice) => {
        if (invoice.status !== "PAID") {
            throw new Error("Seule une facture payée peut être remboursée.");
        }

        return {
            ...invoice,
            status: "REFUNDED",
            paymentReference: request.paymentReference ?? invoice.paymentReference,
            refundReason: request.reason,
            refundedAt: request.refundedAt ?? nowIsoDateTime(),
        };
    });

    return mockResponse(updatedInvoice);
}

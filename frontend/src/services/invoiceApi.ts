import { apiFetch } from "@/lib/api";
import type {
    CancelInvoiceRequest,
    GenerateInvoiceFromReservationRequest,
    Invoice,
    InvoiceSearchParams,
    InvoiceStats,
    IssueInvoiceRequest,
    PageResponse,
    PayInvoiceRequest,
    RefundInvoiceRequest,
    ReservationInvoiceSource,
} from "@/types/invoice";

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

function calculateNights(checkIn: string, checkOut: string): number {
    const msPerDay = 86_400_000;

    return Math.ceil(
        (new Date(checkOut).getTime() - new Date(checkIn).getTime()) / msPerDay
    );
}

export async function getInvoices(
    params: InvoiceSearchParams = {}
): Promise<PageResponse<Invoice>> {
    const queryString = buildQueryString(params);

    return apiFetch<PageResponse<Invoice>>(`/api/invoices${queryString}`);
}

export async function getInvoiceById(id: number): Promise<Invoice> {
    return apiFetch<Invoice>(`/api/invoices/${id}`);
}

export async function getInvoiceByNumber(
    invoiceNumber: string
): Promise<Invoice> {
    return apiFetch<Invoice>(`/api/invoices/number/${invoiceNumber}`);
}

export async function getInvoicesByClientId(
    clientId: number
): Promise<Invoice[]> {
    return apiFetch<Invoice[]>(`/api/invoices/client/${clientId}`);
}

export async function getInvoiceByReservationId(
    reservationId: number
): Promise<Invoice> {
    return apiFetch<Invoice>(`/api/invoices/reservation/${reservationId}`);
}

export async function getInvoiceStats(): Promise<InvoiceStats> {
    const invoicesPage = await getInvoices({
        page: 0,
        size: 1000,
        sort: "createdAt,desc",
    });

    const invoices = invoicesPage.content;

    return {
        total: invoices.length,
        draft: invoices.filter((i) => i.status === "DRAFT").length,
        issued: invoices.filter((i) => i.status === "ISSUED").length,
        paid: invoices.filter((i) => i.status === "PAID").length,
        cancelled: invoices.filter((i) => i.status === "CANCELLED").length,
        refunded: invoices.filter((i) => i.status === "REFUNDED").length,
        totalRevenue: invoices
            .filter((i) => i.status === "PAID")
            .reduce((sum, i) => sum + i.totalAmount, 0),
        pendingAmount: invoices
            .filter((i) => i.status === "ISSUED")
            .reduce((sum, i) => sum + i.totalAmount, 0),
        refundedAmount: invoices
            .filter((i) => i.status === "REFUNDED")
            .reduce((sum, i) => sum + i.totalAmount, 0),
    };
}

interface ReservationResponse {
    id: number;
    roomId: number;
    clientId: number;
    checkInDate: string;
    checkOutDate: string;
    status: string;
    totalPrice: number;
    active: boolean;
}

interface RoomResponse {
    id: number;
    number: string;
    pricePerNight: number;
}

interface ClientResponse {
    id: number;
    firstName: string;
    lastName: string;
}

async function buildInvoiceSource(
    reservation: ReservationResponse,
    existingInvoiceReservationIds: Set<number>
): Promise<ReservationInvoiceSource> {
    const [room, client] = await Promise.all([
        apiFetch<RoomResponse>(`/api/rooms/${reservation.roomId}`),
        apiFetch<ClientResponse>(`/api/clients/${reservation.clientId}`),
    ]);

    return {
        reservationId: reservation.id,
        reservationStatus: reservation.status as ReservationInvoiceSource["reservationStatus"],
        clientId: client.id,
        clientFullName: `${client.firstName} ${client.lastName}`.trim(),
        roomId: room.id,
        roomNumber: room.number,
        checkInDate: reservation.checkInDate,
        checkOutDate: reservation.checkOutDate,
        nights: calculateNights(reservation.checkInDate, reservation.checkOutDate),
        pricePerNight: room.pricePerNight,
        hasActiveInvoice: existingInvoiceReservationIds.has(reservation.id),
    };
}

export async function getReservationInvoiceSources(): Promise<
    ReservationInvoiceSource[]
> {
    const [reservations, invoicesPage] = await Promise.all([
        apiFetch<ReservationResponse[]>(
            "/api/reservations?status=CHECKED_OUT&active=true"
        ),
        getInvoices({ page: 0, size: 1000 }),
    ]);

    const activeStatuses = new Set(["DRAFT", "ISSUED", "PAID"]);
    const invoicedReservationIds = new Set(
        invoicesPage.content
            .filter((inv) => activeStatuses.has(inv.status))
            .map((inv) => inv.reservationId)
    );

    return Promise.all(
        reservations.map((res) =>
            buildInvoiceSource(res, invoicedReservationIds)
        )
    );
}

export async function getReservationInvoiceSourceById(
    reservationId: number
): Promise<ReservationInvoiceSource> {
    const reservation = await apiFetch<ReservationResponse>(
        `/api/reservations/${reservationId}`
    );

    let hasActiveInvoice = false;

    try {
        const invoice = await apiFetch<Invoice>(
            `/api/invoices/reservation/${reservationId}`
        );

        const activeStatuses = new Set(["DRAFT", "ISSUED", "PAID"]);
        hasActiveInvoice = activeStatuses.has(invoice.status);
    } catch {
        hasActiveInvoice = false;
    }

    const invoicedIds = hasActiveInvoice
        ? new Set([reservationId])
        : new Set<number>();

    return buildInvoiceSource(reservation, invoicedIds);
}

export async function generateInvoiceFromReservation(
    reservationId: number,
    request: GenerateInvoiceFromReservationRequest
): Promise<Invoice> {
    return apiFetch<Invoice>(`/api/invoices/reservation/${reservationId}`, {
        method: "POST",
        body: JSON.stringify(request),
    });
}

export async function issueInvoice(
    id: number,
    request: IssueInvoiceRequest = {}
): Promise<Invoice> {
    return apiFetch<Invoice>(`/api/invoices/${id}/issue`, {
        method: "PATCH",
        body: JSON.stringify(request),
    });
}

export async function payInvoice(
    id: number,
    request: PayInvoiceRequest
): Promise<Invoice> {
    return apiFetch<Invoice>(`/api/invoices/${id}/pay`, {
        method: "PATCH",
        body: JSON.stringify(request),
    });
}

export async function cancelInvoice(
    id: number,
    request: CancelInvoiceRequest
): Promise<Invoice> {
    return apiFetch<Invoice>(`/api/invoices/${id}/cancel`, {
        method: "PATCH",
        body: JSON.stringify(request),
    });
}

export async function refundInvoice(
    id: number,
    request: RefundInvoiceRequest
): Promise<Invoice> {
    return apiFetch<Invoice>(`/api/invoices/${id}/refund`, {
        method: "PATCH",
        body: JSON.stringify(request),
    });
}

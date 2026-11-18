"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { ReservationStatusBadge } from "@/components/reservations/ReservationStatusBadge";
import { CancelReservationDialog } from "@/components/reservations/CancelReservationDialog";
import { CheckInDialog } from "@/components/reservations/CheckInDialog";
import { CheckOutDialog } from "@/components/reservations/CheckOutDialog";
import { ReservationService } from "@/services/reservation.service";
import { RoomService } from "@/services/room.service";
import { ClientService } from "@/services/client.service";
import { getInvoiceByReservationId } from "@/services/invoiceApi";
import type { Reservation } from "@/types/reservation";
import type { Invoice } from "@/types/invoice";
import {
    AlertCircle,
    BedDouble,
    Calendar,
    CalendarCheck,
    CheckCircle,
    FileText,
    LogIn,
    LogOut,
    Pencil,
    Plus,
    RefreshCcw,
    User,
    UserX,
    XCircle,
} from "lucide-react";

export default function ReservationDetailPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [reservation, setReservation] = useState<Reservation | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const [showCancel, setShowCancel] = useState(false);
    const [isCancelling, setIsCancelling] = useState(false);
    const [showCheckIn, setShowCheckIn] = useState(false);
    const [isCheckingIn, setIsCheckingIn] = useState(false);
    const [showCheckOut, setShowCheckOut] = useState(false);
    const [isCheckingOut, setIsCheckingOut] = useState(false);
    const [linkedInvoice, setLinkedInvoice] = useState<Invoice | null>(null);
    const [checkOutDone, setCheckOutDone] = useState(false);
    const [roomNumber, setRoomNumber] = useState<string | null>(null);
    const [clientName, setClientName] = useState<string | null>(null);

    const fetchReservation = () => {
        setLoading(true);
        ReservationService.getReservationById(id)
            .then((res) => {
                setReservation(res);
                RoomService.getRoomById(res.roomId)
                    .then((room) => setRoomNumber(room.number))
                    .catch(() => {});
                ClientService.getClientById(res.clientId)
                    .then((client) => setClientName(`${client.firstName} ${client.lastName}`))
                    .catch(() => {});
                if (res.status === "CHECKED_OUT") {
                    getInvoiceByReservationId(res.id)
                        .then(setLinkedInvoice)
                        .catch(() => setLinkedInvoice(null));
                }
            })
            .catch((err) => setError(err instanceof Error ? err.message : "Réservation introuvable"))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchReservation();
    }, [id]);

    const handleConfirm = async () => {
        try {
            await ReservationService.confirmReservation(id);
            fetchReservation();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur");
        }
    };

    const handleCancelConfirm = async () => {
        setIsCancelling(true);
        try {
            await ReservationService.cancelReservation(id);
            setShowCancel(false);
            fetchReservation();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur");
        } finally {
            setIsCancelling(false);
        }
    };

    const handleCheckInConfirm = async () => {
        setIsCheckingIn(true);
        try {
            await ReservationService.checkIn(id);
            setShowCheckIn(false);
            fetchReservation();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur");
        } finally {
            setIsCheckingIn(false);
        }
    };

    const handleCheckOutConfirm = async () => {
        setIsCheckingOut(true);
        try {
            await ReservationService.checkOut(id);
            setShowCheckOut(false);
            setCheckOutDone(true);
            fetchReservation();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur");
        } finally {
            setIsCheckingOut(false);
        }
    };

    const handleNoShow = async () => {
        try {
            await ReservationService.noShow(id);
            fetchReservation();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur");
        }
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-[var(--hms-text-muted)]">
                    <RefreshCcw className="mr-2 h-4 w-4 animate-spin" strokeWidth={1.8} />
                    Chargement de la réservation...
                </div>
            </AppLayout>
        );
    }

    if (error || !reservation) {
        return (
            <AppLayout>
                <HmsCard>
                    <div className="flex items-start gap-4">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" strokeWidth={1.8} />
                        <div>
                            <p className="font-semibold text-red-700">Réservation introuvable</p>
                            <p className="mt-1 text-sm text-red-600">{error}</p>
                        </div>
                    </div>
                </HmsCard>
            </AppLayout>
        );
    }

    const formatDate = (dateStr: string) =>
        new Date(dateStr).toLocaleDateString("fr-FR", { weekday: "long", day: "numeric", month: "long", year: "numeric" });

    const nights = Math.ceil(
        (new Date(reservation.checkOutDate).getTime() - new Date(reservation.checkInDate).getTime()) / (1000 * 60 * 60 * 24)
    );

    const tiles = [
        { icon: BedDouble, label: "Chambre", value: roomNumber ? `Chambre ${roomNumber}` : `#${reservation.roomId}`, href: `/rooms/${reservation.roomId}` },
        { icon: User, label: "Client", value: clientName ?? `#${reservation.clientId}`, href: `/clients/${reservation.clientId}` },
        { icon: Calendar, label: "Arrivée", value: formatDate(reservation.checkInDate), href: undefined },
        { icon: CalendarCheck, label: "Départ", value: formatDate(reservation.checkOutDate), href: undefined },
    ];

    return (
        <AppLayout>
            <PageHeader
                backHref="/reservations"
                eyebrow={`RES-${reservation.id}`}
                title={`Réservation #${reservation.id}`}
                description="Détails complets de la réservation, actions de gestion du séjour et suivi du statut."
                actions={
                    <>
                        {reservation.status === "CREATED" && (
                            <Link href={`/reservations/${id}/edit`}>
                                <HmsButton>
                                    <Pencil className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                    Modifier
                                </HmsButton>
                            </Link>
                        )}
                        {(reservation.status === "CREATED" || reservation.status === "CONFIRMED") && (
                            <HmsButton variant="danger" onClick={() => setShowCancel(true)}>
                                <XCircle className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Annuler
                            </HmsButton>
                        )}
                    </>
                }
            />

            <HmsCard>
                <div className="flex items-center justify-between">
                    <ReservationStatusBadge status={reservation.status} />
                    <span className="text-sm font-medium text-[var(--hms-text-muted)]">
                        {nights} nuit{nights > 1 ? "s" : ""}
                    </span>
                </div>

                {reservation.notes && (
                    <p className="mt-5 text-base text-[var(--hms-text-muted)]">{reservation.notes}</p>
                )}

                <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                    {tiles.map(({ icon: Icon, label, value, href }) => {
                        const content = (
                            <>
                                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-[var(--hms-text-muted)] shadow-sm">
                                    <Icon className="h-[18px] w-[18px]" strokeWidth={1.8} />
                                </div>
                                <p className="mt-4 text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">{label}</p>
                                <p className="mt-1 text-lg font-bold text-[var(--hms-text)]">{value}</p>
                            </>
                        );
                        return href ? (
                            <Link key={label} href={href} className="rounded-2xl bg-slate-50 p-5 ring-1 ring-inset ring-[var(--hms-soft-border)] transition hover:shadow-sm">
                                {content}
                            </Link>
                        ) : (
                            <div key={label} className="rounded-2xl bg-slate-50 p-5 ring-1 ring-inset ring-[var(--hms-soft-border)]">
                                {content}
                            </div>
                        );
                    })}
                </div>
            </HmsCard>

            <HmsCard className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <p className="text-sm font-medium text-[var(--hms-text-muted)]">Prix total</p>
                    <p className="mt-1 text-4xl font-bold text-[var(--hms-text)]">{reservation.totalPrice} DH</p>
                </div>

                <div className="flex flex-wrap gap-3">
                    {reservation.status === "CREATED" && (
                        <HmsButton onClick={handleConfirm}>
                            <CheckCircle className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Confirmer
                        </HmsButton>
                    )}
                    {reservation.status === "CONFIRMED" && (
                        <>
                            <HmsButton onClick={() => setShowCheckIn(true)}>
                                <LogIn className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Check-in
                            </HmsButton>
                            <HmsButton variant="secondary" onClick={handleNoShow}>
                                <UserX className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                No-show
                            </HmsButton>
                        </>
                    )}
                    {reservation.status === "CHECKED_IN" && (
                        <HmsButton onClick={() => setShowCheckOut(true)}>
                            <LogOut className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Check-out
                        </HmsButton>
                    )}
                </div>
            </HmsCard>

            {checkOutDone && !linkedInvoice && (
                <div className="flex items-center justify-between rounded-2xl border border-emerald-200 bg-emerald-50 p-5">
                    <div className="flex items-center gap-3">
                        <CheckCircle className="h-5 w-5 text-emerald-600" strokeWidth={1.8} aria-hidden="true" />
                        <p className="text-sm font-semibold text-emerald-800">
                            Check-out effectué. Vous pouvez maintenant générer la facture.
                        </p>
                    </div>
                    <Link href={`/invoices/create?reservationId=${id}`}>
                        <HmsButton>
                            <FileText className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Générer la facture
                        </HmsButton>
                    </Link>
                </div>
            )}

            {reservation.status === "CHECKED_OUT" && (
                <HmsCard className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <FileText className="h-5 w-5 text-[var(--hms-text-muted)]" strokeWidth={1.8} aria-hidden="true" />
                        <div>
                            <p className="text-sm font-bold text-[var(--hms-text)]">Facturation</p>
                            <p className="text-sm text-[var(--hms-text-muted)]">
                                {linkedInvoice
                                    ? `Facture ${linkedInvoice.invoiceNumber} — ${linkedInvoice.status === "PAID" ? "Payée" : linkedInvoice.status === "ISSUED" ? "Émise" : linkedInvoice.status === "DRAFT" ? "Brouillon" : linkedInvoice.status === "CANCELLED" ? "Annulée" : "Remboursée"}`
                                    : "Aucune facture générée pour cette réservation."}
                            </p>
                        </div>
                    </div>
                    {linkedInvoice ? (
                        <Link href={`/invoices/${linkedInvoice.id}`}>
                            <HmsButton variant="secondary">
                                <FileText className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Voir la facture
                            </HmsButton>
                        </Link>
                    ) : (
                        <Link href={`/invoices/create?reservationId=${id}`}>
                            <HmsButton>
                                <Plus className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Générer la facture
                            </HmsButton>
                        </Link>
                    )}
                </HmsCard>
            )}

            <CancelReservationDialog
                isOpen={showCancel}
                onClose={() => setShowCancel(false)}
                onConfirm={handleCancelConfirm}
                reservationId={reservation.id}
                isLoading={isCancelling}
            />

            <CheckInDialog
                isOpen={showCheckIn}
                onClose={() => setShowCheckIn(false)}
                onConfirm={handleCheckInConfirm}
                reservationId={reservation.id}
                isLoading={isCheckingIn}
            />

            <CheckOutDialog
                isOpen={showCheckOut}
                onClose={() => setShowCheckOut(false)}
                onConfirm={handleCheckOutConfirm}
                reservationId={reservation.id}
                isLoading={isCheckingOut}
            />
        </AppLayout>
    );
}

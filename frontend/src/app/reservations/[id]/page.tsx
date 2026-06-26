'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { ReservationStatusBadge } from '@/components/reservations/ReservationStatusBadge';
import { CancelReservationDialog } from '@/components/reservations/CancelReservationDialog';
import { CheckInDialog } from '@/components/reservations/CheckInDialog';
import { CheckOutDialog } from '@/components/reservations/CheckOutDialog';
import { ReservationService } from '@/services/reservation.service';
import { Reservation } from '@/types/reservation';
import {
    AlertCircle,
    BedDouble,
    Calendar,
    CalendarCheck,
    DollarSign,
    LogIn,
    LogOut,
    Pencil,
    RefreshCcw,
    User,
    XCircle,
    CheckCircle,
    UserX,
} from 'lucide-react';

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

    const fetchReservation = () => {
        setLoading(true);
        ReservationService.getReservationById(id)
            .then(setReservation)
            .catch((err) => setError(err instanceof Error ? err.message : 'Réservation introuvable'))
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
            alert(err instanceof Error ? err.message : 'Erreur');
        }
    };

    const handleCancelConfirm = async () => {
        setIsCancelling(true);
        try {
            await ReservationService.cancelReservation(id);
            setShowCancel(false);
            fetchReservation();
        } catch (err) {
            alert(err instanceof Error ? err.message : 'Erreur');
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
            alert(err instanceof Error ? err.message : 'Erreur');
        } finally {
            setIsCheckingIn(false);
        }
    };

    const handleCheckOutConfirm = async () => {
        setIsCheckingOut(true);
        try {
            await ReservationService.checkOut(id);
            setShowCheckOut(false);
            fetchReservation();
        } catch (err) {
            alert(err instanceof Error ? err.message : 'Erreur');
        } finally {
            setIsCheckingOut(false);
        }
    };

    const handleNoShow = async () => {
        try {
            await ReservationService.noShow(id);
            fetchReservation();
        } catch (err) {
            alert(err instanceof Error ? err.message : 'Erreur');
        }
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-zinc-400">
                    <RefreshCcw size={18} className="mr-2 animate-spin" />
                    Chargement de la réservation...
                </div>
            </AppLayout>
        );
    }

    if (error || !reservation) {
        return (
            <AppLayout>
                <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                    <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
                    <div>
                        <p className="font-semibold text-red-700">Réservation introuvable</p>
                        <p className="mt-1 text-sm text-red-600">{error}</p>
                    </div>
                </div>
            </AppLayout>
        );
    }

    const formatDate = (dateStr: string) =>
        new Date(dateStr).toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

    const nights = Math.ceil(
        (new Date(reservation.checkOutDate).getTime() - new Date(reservation.checkInDate).getTime()) / (1000 * 60 * 60 * 24)
    );

    const tiles = [
        { icon: BedDouble, label: 'Chambre', value: `#${reservation.roomId}`, href: `/rooms/${reservation.roomId}` },
        { icon: User, label: 'Client', value: `#${reservation.clientId}`, href: `/clients/${reservation.clientId}` },
        { icon: Calendar, label: 'Arrivée', value: formatDate(reservation.checkInDate), href: undefined },
        { icon: CalendarCheck, label: 'Départ', value: formatDate(reservation.checkOutDate), href: undefined },
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
                        {reservation.status === 'CREATED' && (
                            <Link
                                href={`/reservations/${id}/edit`}
                                className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-800"
                            >
                                <Pencil size={16} />
                                Modifier
                            </Link>
                        )}
                        {(reservation.status === 'CREATED' || reservation.status === 'CONFIRMED') && (
                            <button
                                onClick={() => setShowCancel(true)}
                                className="inline-flex items-center gap-2 rounded-2xl bg-red-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-red-600"
                            >
                                <XCircle size={16} />
                                Annuler
                            </button>
                        )}
                    </>
                }
            />

            <div className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
                <div className="flex items-center justify-between">
                    <ReservationStatusBadge status={reservation.status} />
                    <span className="text-sm font-medium text-zinc-400">
                        {nights} nuit{nights > 1 ? 's' : ''}
                    </span>
                </div>

                {reservation.notes && (
                    <p className="mt-5 text-base text-zinc-600">{reservation.notes}</p>
                )}

                <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                    {tiles.map(({ icon: Icon, label, value, href }) => {
                        const content = (
                            <>
                                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-zinc-500 shadow-sm">
                                    <Icon size={18} />
                                </div>
                                <p className="mt-4 text-xs font-semibold uppercase tracking-wider text-zinc-400">{label}</p>
                                <p className="mt-1 text-lg font-bold text-zinc-900">{value}</p>
                            </>
                        );
                        return href ? (
                            <Link key={label} href={href} className="rounded-2xl border border-zinc-100 bg-zinc-50 p-5 transition hover:border-zinc-300 hover:shadow-sm">
                                {content}
                            </Link>
                        ) : (
                            <div key={label} className="rounded-2xl border border-zinc-100 bg-zinc-50 p-5">
                                {content}
                            </div>
                        );
                    })}
                </div>
            </div>

            <div className="flex flex-col gap-6 rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <p className="text-sm font-medium text-zinc-500">Prix total</p>
                    <p className="mt-1 text-4xl font-bold text-zinc-950">{reservation.totalPrice} DH</p>
                </div>

                <div className="flex flex-wrap gap-3">
                    {reservation.status === 'CREATED' && (
                        <button
                            onClick={handleConfirm}
                            className="inline-flex items-center gap-2 rounded-2xl bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-600"
                        >
                            <CheckCircle size={16} />
                            Confirmer
                        </button>
                    )}
                    {reservation.status === 'CONFIRMED' && (
                        <>
                            <button
                                onClick={() => setShowCheckIn(true)}
                                className="inline-flex items-center gap-2 rounded-2xl bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-600"
                            >
                                <LogIn size={16} />
                                Check-in
                            </button>
                            <button
                                onClick={handleNoShow}
                                className="inline-flex items-center gap-2 rounded-2xl border border-orange-200 bg-white px-4 py-2.5 text-sm font-semibold text-orange-600 transition hover:bg-orange-50"
                            >
                                <UserX size={16} />
                                No-show
                            </button>
                        </>
                    )}
                    {reservation.status === 'CHECKED_IN' && (
                        <button
                            onClick={() => setShowCheckOut(true)}
                            className="inline-flex items-center gap-2 rounded-2xl bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-600"
                        >
                            <LogOut size={16} />
                            Check-out
                        </button>
                    )}
                </div>
            </div>

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

import { Calendar, CalendarCheck, CheckCircle, LogIn, XCircle } from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import type { Reservation } from "@/types/reservation";

interface ReservationStatsCardsProps {
    reservations: Reservation[];
}

export function ReservationStatsCards({ reservations }: ReservationStatsCardsProps) {
    const total = reservations.length;
    const created = reservations.filter((r) => r.status === "CREATED").length;
    const confirmed = reservations.filter((r) => r.status === "CONFIRMED").length;
    const checkedIn = reservations.filter((r) => r.status === "CHECKED_IN").length;
    const checkedOut = reservations.filter((r) => r.status === "CHECKED_OUT").length;
    const cancelled = reservations.filter((r) => r.status === "CANCELLED").length;

    const statItems = [
        { label: "Créées", value: created, icon: Calendar, color: "text-slate-500" },
        { label: "Confirmées", value: confirmed, icon: CalendarCheck, color: "text-indigo-500" },
        { label: "Check-in", value: checkedIn, icon: LogIn, color: "text-orange-500" },
        { label: "Check-out", value: checkedOut, icon: CheckCircle, color: "text-emerald-500" },
        { label: "Annulées", value: cancelled, icon: XCircle, color: "text-red-500" },
    ];

    return (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
            <HmsCard className="flex flex-col gap-0.5">
                <p className="text-xs font-medium text-[var(--hms-text-muted)]">Total</p>
                <p className="text-3xl font-bold text-[var(--hms-text)]">{total}</p>
                <p className="text-xs text-[var(--hms-text-muted)]">réservations</p>
            </HmsCard>

            {statItems.map(({ label, value, icon: Icon, color }) => (
                <HmsCard key={label} className="flex items-center gap-3">
                    <Icon className={`h-5 w-5 shrink-0 ${color}`} strokeWidth={1.8} aria-hidden="true" />
                    <div>
                        <p className="text-xs font-medium text-[var(--hms-text-muted)]">{label}</p>
                        <p className="text-xl font-bold text-[var(--hms-text)]">{value}</p>
                    </div>
                </HmsCard>
            ))}
        </div>
    );
}

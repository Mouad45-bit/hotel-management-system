import { cn } from "@/lib/utils";
import type { ReservationStatus } from "@/types/reservation";

const STATUS_BADGE_CLASSES: Record<ReservationStatus, string> = {
    CREATED: "bg-blue-50 text-blue-700 ring-blue-200",
    CONFIRMED: "bg-indigo-50 text-indigo-700 ring-indigo-200",
    CHECKED_IN: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    CHECKED_OUT: "bg-zinc-100 text-zinc-600 ring-zinc-200",
    CANCELLED: "bg-red-50 text-red-700 ring-red-200",
    NO_SHOW: "bg-orange-50 text-orange-700 ring-orange-200",
};

const STATUS_LABELS: Record<ReservationStatus, string> = {
    CREATED: "Créée",
    CONFIRMED: "Confirmée",
    CHECKED_IN: "Check-in",
    CHECKED_OUT: "Check-out",
    CANCELLED: "Annulée",
    NO_SHOW: "No-show",
};

interface ReservationStatusBadgeProps {
    status: ReservationStatus;
    className?: string;
}

export function ReservationStatusBadge({ status, className }: ReservationStatusBadgeProps) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                STATUS_BADGE_CLASSES[status] ?? STATUS_BADGE_CLASSES.CREATED,
                className
            )}
        >
            {STATUS_LABELS[status] ?? status}
        </span>
    );
}

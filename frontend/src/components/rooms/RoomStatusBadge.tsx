import { cn } from "@/lib/utils";
import type { RoomStatus } from "@/types/room";

const STATUS_BADGE_CLASSES: Record<RoomStatus, string> = {
    AVAILABLE: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    RESERVED: "bg-indigo-50 text-indigo-700 ring-indigo-200",
    OCCUPIED: "bg-orange-50 text-orange-700 ring-orange-200",
    CLEANING: "bg-blue-50 text-blue-700 ring-blue-200",
    MAINTENANCE: "bg-zinc-50 text-zinc-700 ring-zinc-200",
    OUT_OF_SERVICE: "bg-red-50 text-red-700 ring-red-200",
};

const STATUS_LABELS: Record<RoomStatus, string> = {
    AVAILABLE: "Disponible",
    RESERVED: "Réservée",
    OCCUPIED: "Occupée",
    CLEANING: "Nettoyage",
    MAINTENANCE: "Maintenance",
    OUT_OF_SERVICE: "Hors service",
};

interface RoomStatusBadgeProps {
    status: RoomStatus;
    className?: string;
}

export function RoomStatusBadge({ status, className }: RoomStatusBadgeProps) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                STATUS_BADGE_CLASSES[status] ?? "bg-zinc-50 text-zinc-700 ring-zinc-200",
                className
            )}
        >
            {STATUS_LABELS[status] ?? status}
        </span>
    );
}

import { RoomStatus } from "@/types/room";
import { cn } from "@/lib/utils";

interface RoomStatusBadgeProps {
    status: RoomStatus;
    className?: string;
}

export function RoomStatusBadge({ status, className }: RoomStatusBadgeProps) {
    // Mapping strict des couleurs et libellés selon le cahier des charges
    const getStatusConfig = (status: RoomStatus) => {
        switch (status) {
            case "AVAILABLE":
                return { label: "Disponible", className: "bg-emerald-50 text-emerald-700 ring-emerald-200" };
            case "RESERVED":
                return { label: "Réservée", className: "bg-indigo-50 text-indigo-700 ring-indigo-200" };
            case "OCCUPIED":
                return { label: "Occupée", className: "bg-orange-50 text-orange-700 ring-orange-200" };
            case "CLEANING":
                return { label: "Nettoyage", className: "bg-blue-50 text-blue-700 ring-blue-200" };
            case "MAINTENANCE":
                return { label: "Maintenance", className: "bg-zinc-50 text-zinc-700 ring-zinc-200" };
            case "OUT_OF_SERVICE":
                return { label: "Hors service", className: "bg-red-50 text-red-700 ring-red-200" };
            default:
                return { label: status, className: "bg-gray-50 text-gray-700 ring-gray-200" };
        }
    };

    const config = getStatusConfig(status);

    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset",
                config.className,
                className
            )}
        >
      {config.label}
    </span>
    );
}

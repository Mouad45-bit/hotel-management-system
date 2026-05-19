import { RoomStatus, ROOM_STATUS_LABELS, ROOM_STATUS_BADGE_CLASSES } from "@/types/room";
import { cn } from "@/lib/utils";

// 1. Définition des propriétés (Les "paramètres" du composant)
interface RoomStatusBadgeProps {
    status: RoomStatus;
    className?: string;
}

// 2. Le composant React
export function RoomStatusBadge({ status, className }: RoomStatusBadgeProps) {

    const label = ROOM_STATUS_LABELS[status];
    const colorClasses = ROOM_STATUS_BADGE_CLASSES[status] ?? "bg-gray-50 text-gray-700 ring-gray-500/20";

    return (
        <span
            className={cn(
                // Classes de base communes à tous les badges (forme, texte, bordure)
                "inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset",
                // Classes spécifiques à la couleur du statut actuel
                colorClasses,
                // Permet d'ajouter d'autres classes depuis le composant parent si besoin
                className
            )}
        >
            {label}
        </span>
    );
}

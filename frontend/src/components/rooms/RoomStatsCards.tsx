import { Room } from "@/types/room";

interface RoomStatsCardsProps {
    rooms: Room[];
}

export function RoomStatsCards({ rooms }: RoomStatsCardsProps) {
    const total = rooms.length;
    const available = rooms.filter(r => r.status === "AVAILABLE").length;
    const occupied = rooms.filter(r => r.status === "OCCUPIED").length;
    const reserved = rooms.filter(r => r.status === "RESERVED").length;
    const maintenanceOrCleaning = rooms.filter(
        r => r.status === "CLEANING" || r.status === "MAINTENANCE" || r.status === "OUT_OF_SERVICE"
    ).length;

    const cards = [
        { label: "Total Chambres", value: total, color: "text-zinc-950" },
        { label: "Disponibles", value: available, color: "text-emerald-600" },
        { label: "Occupées", value: occupied, color: "text-orange-600" },
        { label: "Réservées", value: reserved, color: "text-blue-600" },
        { label: "Maintenance / Nettoyage", value: maintenanceOrCleaning, color: "text-amber-600" },
    ];

    return (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            {cards.map(card => (
                <div
                    key={card.label}
                    className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm"
                >
                    <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider">
                        {card.label}
                    </p>
                    <p className={`mt-2 text-3xl font-semibold ${card.color}`}>
                        {card.value}
                    </p>
                </div>
            ))}
        </div>
    );
}

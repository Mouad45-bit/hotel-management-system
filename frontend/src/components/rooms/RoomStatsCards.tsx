import { RoomStats } from "@/types/room";
import { CheckCircle, User, Calendar, RefreshCcw, Wrench, Ban } from "lucide-react";

interface RoomStatsCardsProps {
    stats: RoomStats | null;
}

export function RoomStatsCards({ stats }: RoomStatsCardsProps) {
    if (!stats) return null;

    const statItems = [
        { label: "Disponibles", value: stats.available, icon: CheckCircle, color: "text-emerald-500" },
        { label: "Occupées", value: stats.occupied, icon: User, color: "text-orange-500" },
        { label: "Réservées", value: stats.reserved, icon: Calendar, color: "text-indigo-500" },
        { label: "Nettoyage", value: stats.cleaning, icon: RefreshCcw, color: "text-blue-500" },
        { label: "Maintenance", value: stats.maintenance, icon: Wrench, color: "text-zinc-500" },
        { label: "Hors service", value: stats.outOfService, icon: Ban, color: "text-red-500" },
    ];

    return (
        <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-7 gap-3">
            <div className="col-span-2 sm:col-span-1 bg-white p-4 rounded-xl ring-1 ring-zinc-200 shadow-sm flex flex-col gap-0.5">
                <p className="text-xs font-medium text-zinc-500">Total</p>
                <p className="text-3xl font-bold text-zinc-900">{stats.total}</p>
                <p className="text-xs text-zinc-400">chambres</p>
            </div>

            {statItems.map(({ label, value, icon: Icon, color }) => (
                <div key={label} className="bg-white p-4 rounded-xl ring-1 ring-zinc-200 shadow-sm flex items-center gap-3">
                    <Icon size={20} className={`${color} shrink-0`} />
                    <div>
                        <p className="text-xs font-medium text-zinc-500">{label}</p>
                        <p className="text-xl font-bold text-zinc-900">{value}</p>
                    </div>
                </div>
            ))}
        </div>
    );
}

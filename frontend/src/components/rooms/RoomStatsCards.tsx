import { Ban, Calendar, CheckCircle, RefreshCcw, User, Wrench } from "lucide-react";
import type { RoomStats } from "@/types/room";
import { HmsCard } from "@/components/hms/HmsCard";

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
        { label: "Maintenance", value: stats.maintenance, icon: Wrench, color: "text-slate-500" },
        { label: "Hors service", value: stats.outOfService, icon: Ban, color: "text-red-500" },
    ];

    return (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-7">
            <HmsCard className="col-span-2 flex flex-col gap-0.5 sm:col-span-1">
                <p className="text-xs font-medium text-[var(--hms-text-muted)]">Total</p>
                <p className="text-3xl font-bold text-[var(--hms-text)]">{stats.total}</p>
                <p className="text-xs text-[var(--hms-text-muted)]">chambres</p>
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

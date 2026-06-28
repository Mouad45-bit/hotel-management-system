import { CheckCircle, Users, UserX } from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import type { Client } from "@/types/client";

interface ClientStatsCardsProps {
    clients: Client[];
    showInactive: boolean;
}

export function ClientStatsCards({ clients, showInactive }: ClientStatsCardsProps) {
    if (showInactive) return null;

    const total = clients.length;
    const active = clients.filter((c) => c.active !== false).length;
    const inactive = total - active;

    const statItems = [
        { label: "Actifs", value: active, icon: CheckCircle, color: "text-emerald-500" },
        { label: "Désactivés", value: inactive, icon: UserX, color: "text-red-500" },
    ];

    return (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <HmsCard className="flex flex-col gap-0.5">
                <p className="text-xs font-medium text-[var(--hms-text-muted)]">Total</p>
                <p className="text-3xl font-bold text-[var(--hms-text)]">{total}</p>
                <p className="text-xs text-[var(--hms-text-muted)]">clients</p>
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

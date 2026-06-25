"use client";

import {
    Ban,
    CheckCircle2,
    Clock3,
    Play,
    UserPlus,
} from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskTimelineProps {
    task: HousekeepingTask;
}

export function HousekeepingTaskTimeline({ task }: HousekeepingTaskTimelineProps) {
    const events = [
        {
            label: "Création",
            date: task.createdAt,
            description: "Tâche créée au statut À faire.",
            icon: Clock3,
        },
        task.assignedAgentId
            ? {
                  label: "Assignation",
                  date: task.updatedAt,
                  description: `Assignée à ${task.assignedAgentName}.`,
                  icon: UserPlus,
              }
            : null,
        task.startedAt
            ? {
                  label: "Démarrage",
                  date: task.startedAt,
                  description: "La chambre est passée en nettoyage.",
                  icon: Play,
              }
            : null,
        task.completedAt
            ? {
                  label: "Terminaison",
                  date: task.completedAt,
                  description: "La tâche est terminée et la chambre peut redevenir disponible.",
                  icon: CheckCircle2,
              }
            : null,
        task.cancelledAt
            ? {
                  label: "Annulation",
                  date: task.cancelledAt,
                  description: task.cancellationReason ?? "Tâche annulée.",
                  icon: Ban,
              }
            : null,
    ].filter(Boolean);

    return (
        <HmsCard className="p-6">
            <h3 className="text-lg font-bold text-[var(--hms-text)]">Historique</h3>
            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                Historique des événements connus pour cette tâche.
            </p>
            <div className="mt-5 space-y-4">
                {events.map((event) => {
                    const item = event as NonNullable<(typeof events)[number]>;
                    const Icon = item.icon;

                    return (
                        <div key={`${item.label}-${item.date}`} className="flex gap-3">
                            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-zinc-100 text-zinc-700">
                                <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                            </div>
                            <div>
                                <p className="text-sm font-bold text-[var(--hms-text)]">
                                    {item.label}
                                </p>
                                <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                                    {item.description}
                                </p>
                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                    <HousekeepingDate value={item.date} withTime className="text-xs text-[var(--hms-text-muted)]" />
                                </p>
                            </div>
                        </div>
                    );
                })}
            </div>
        </HmsCard>
    );
}

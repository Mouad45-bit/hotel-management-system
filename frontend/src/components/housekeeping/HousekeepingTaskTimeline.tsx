"use client";

import {
    CheckCircleIcon,
    ClockIcon,
    NoSymbolIcon,
    PlayIcon,
    UserPlusIcon,
} from "@heroicons/react/24/outline";
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
            icon: ClockIcon,
        },
        task.assignedAgentId
            ? {
                  label: "Assignation",
                  date: task.updatedAt,
                  description: `Assignée à ${task.assignedAgentName}.`,
                  icon: UserPlusIcon,
              }
            : null,
        task.startedAt
            ? {
                  label: "Démarrage",
                  date: task.startedAt,
                  description: "La chambre est passée en nettoyage.",
                  icon: PlayIcon,
              }
            : null,
        task.completedAt
            ? {
                  label: "Terminaison",
                  date: task.completedAt,
                  description: "La tâche est terminée et la chambre peut redevenir disponible.",
                  icon: CheckCircleIcon,
              }
            : null,
        task.cancelledAt
            ? {
                  label: "Annulation",
                  date: task.cancelledAt,
                  description: task.cancellationReason ?? "Tâche annulée.",
                  icon: NoSymbolIcon,
              }
            : null,
    ].filter(Boolean);

    return (
        <HmsCard>
            <h3 className="text-sm font-semibold text-zinc-950">Timeline</h3>
            <p className="mt-1 text-sm text-zinc-500">
                Historique des événements connus pour cette tâche.
            </p>
            <div className="mt-5 space-y-4">
                {events.map((event) => {
                    const item = event as NonNullable<(typeof events)[number]>;
                    const Icon = item.icon;

                    return (
                        <div key={`${item.label}-${item.date}`} className="flex gap-3">
                            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-zinc-100 text-zinc-700">
                                <Icon className="h-5 w-5" />
                            </div>
                            <div>
                                <p className="text-sm font-semibold text-zinc-950">
                                    {item.label}
                                </p>
                                <p className="mt-1 text-sm text-zinc-500">
                                    {item.description}
                                </p>
                                <p className="mt-1 text-xs text-zinc-400">
                                    <HousekeepingDate value={item.date} withTime className="text-xs text-zinc-400" />
                                </p>
                            </div>
                        </div>
                    );
                })}
            </div>
        </HmsCard>
    );
}

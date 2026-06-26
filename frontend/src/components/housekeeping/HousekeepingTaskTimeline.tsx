"use client";

import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskTimelineProps {
    task: HousekeepingTask;
}

interface TimelineItem {
    label: string;
    date?: string | null;
    description: string;
}

export function HousekeepingTaskTimeline({ task }: HousekeepingTaskTimelineProps) {
    const items: TimelineItem[] = [
        {
            label: "Création",
            date: task.createdAt,
            description: "Tâche créée au statut À faire.",
        },
        {
            label: "Assignation",
            date: task.assignedAgentId ? task.updatedAt : null,
            description: task.assignedAgentId
                ? `Assignée à ${task.assignedAgentName}.`
                : "Assignation non effectuée.",
        },
        {
            label: "Démarrage",
            date: task.startedAt,
            description: "La chambre passe en nettoyage quand la tâche démarre.",
        },
        {
            label: "Terminaison",
            date: task.completedAt,
            description: "La tâche terminée peut remettre la chambre en disponibilité.",
        },
        {
            label: "Annulation",
            date: task.cancelledAt,
            description: task.cancellationReason ?? "La tâche peut être annulée avec motif.",
        },
    ];

    return (
        <HmsCard className="p-6">
            <h3 className="text-lg font-bold text-[var(--hms-text)]">Historique</h3>

            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                Historique des événements connus pour cette tâche.
            </p>

            <div className="mt-6">
                {items.map((item, index) => {
                    const isDone = Boolean(item.date);
                    const isLast = index === items.length - 1;

                    return (
                        <div
                            key={item.label}
                            className="flex gap-3 pb-5 last:pb-0"
                        >
                            <div className="relative flex w-4 shrink-0 justify-center">
                                <div
                                    className={
                                        isDone
                                            ? "relative z-10 mt-1 h-3 w-3 rounded-full bg-emerald-600 ring-4 ring-emerald-50"
                                            : "relative z-10 mt-1 h-3 w-3 rounded-full bg-slate-300 ring-4 ring-slate-50"
                                    }
                                />

                                {!isLast && (
                                    <div
                                        className={
                                            isDone
                                                ? "absolute bottom-[-4px] top-4 w-px bg-emerald-200"
                                                : "absolute bottom-[-4px] top-4 w-px bg-[var(--hms-soft-border)]"
                                        }
                                    />
                                )}
                            </div>

                            <div className="min-w-0 flex-1">
                                <p
                                    className={
                                        isDone
                                            ? "text-sm font-semibold text-[var(--hms-text)]"
                                            : "text-sm font-medium text-[rgba(13,9,7,0.42)]"
                                    }
                                >
                                    {item.label}
                                </p>

                                <p className="mt-1">
                                    {isDone ? (
                                        <HousekeepingDate
                                            value={item.date}
                                            withTime
                                            className="text-xs text-[var(--hms-text-muted)]"
                                        />
                                    ) : (
                                        <span className="text-xs text-[rgba(13,9,7,0.38)]">
                                            Non effectuée
                                        </span>
                                    )}
                                </p>

                                <p
                                    className={
                                        isDone
                                            ? "mt-1 text-xs leading-5 text-[var(--hms-text-muted)]"
                                            : "mt-1 text-xs leading-5 text-[rgba(13,9,7,0.42)]"
                                    }
                                >
                                    {item.description}
                                </p>
                            </div>
                        </div>
                    );
                })}
            </div>
        </HmsCard>
    );
}

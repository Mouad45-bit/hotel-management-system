"use client";

import {
    CalendarDays,
    Home,
    UserRound,
} from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import { PriorityBadge } from "@/components/housekeeping/PriorityBadge";
import { TaskTypeBadge } from "@/components/housekeeping/TaskTypeBadge";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskInfoCardsProps {
    task: HousekeepingTask;
}

export function HousekeepingTaskInfoCards({ task }: HousekeepingTaskInfoCardsProps) {
    return (
        <div className="space-y-6">
            <div className="grid gap-4 md:grid-cols-3">
                <HmsCard className="p-6">
                    <div className="flex items-start gap-3">
                        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-zinc-100 text-zinc-700">
                            <Home aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        </div>
                        <div>
                            <p className="text-sm font-medium text-[var(--hms-text-muted)]">Chambre</p>
                            <p className="mt-1 text-lg font-bold text-[var(--hms-text)]">
                                {task.roomNumber}
                            </p>
                            <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                Room ID #{task.roomId}
                            </p>
                        </div>
                    </div>
                </HmsCard>
                <HmsCard className="p-6">
                    <div className="flex items-start gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-blue-50 text-blue-700">
                            <UserRound aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        </div>
                        <div>
                            <p className="text-sm font-medium text-[var(--hms-text-muted)]">Agent</p>
                            <p className="mt-1 text-lg font-bold text-[var(--hms-text)]">
                                {task.assignedAgentName ?? "Non assignée"}
                            </p>
                            <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                {task.assignedAgentId
                                    ? `Agent #${task.assignedAgentId}`
                                    : "Affectation requise"}
                            </p>
                        </div>
                    </div>
                </HmsCard>
                <HmsCard className="p-6">
                    <div className="flex items-start gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-700">
                            <CalendarDays aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        </div>
                        <div>
                            <p className="text-sm font-medium text-[var(--hms-text-muted)]">Date planifiée</p>
                            <p className="mt-1 text-lg font-bold text-[var(--hms-text)]">
                                <HousekeepingDate value={task.scheduledDate} />
                            </p>
                            <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                Réservation {task.reservationId ? `#${task.reservationId}` : "non liée"}
                            </p>
                        </div>
                    </div>
                </HmsCard>
            </div>

            <HmsCard className="p-6">
                <div className="grid gap-6 md:grid-cols-2">
                    <div>
                        <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Statut et priorité
                        </p>
                        <div className="mt-3 flex flex-wrap gap-2">
                            <HousekeepingStatusBadge status={task.status} />
                            <PriorityBadge priority={task.priority} />
                            <TaskTypeBadge type={task.type} />
                        </div>
                    </div>
                    <div>
                        <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Notes
                        </p>
                        <p className="mt-3 text-sm leading-6 text-[var(--hms-text)]">
                            {task.notes || "Aucune note renseignée."}
                        </p>
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}

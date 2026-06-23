"use client";

import {
    CalendarDaysIcon,
    HomeIcon,
    UserCircleIcon,
} from "@heroicons/react/24/outline";
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
                <HmsCard>
                    <div className="flex items-start gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-stone-100 text-stone-700">
                            <HomeIcon className="h-5 w-5" />
                        </div>
                        <div>
                            <p className="text-sm text-zinc-500">Chambre</p>
                            <p className="mt-1 text-lg font-semibold text-zinc-950">
                                {task.roomNumber}
                            </p>
                            <p className="mt-1 text-xs text-zinc-500">
                                Room ID #{task.roomId}
                            </p>
                        </div>
                    </div>
                </HmsCard>
                <HmsCard>
                    <div className="flex items-start gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-blue-50 text-blue-700">
                            <UserCircleIcon className="h-5 w-5" />
                        </div>
                        <div>
                            <p className="text-sm text-zinc-500">Agent</p>
                            <p className="mt-1 text-lg font-semibold text-zinc-950">
                                {task.assignedAgentName ?? "Non assignée"}
                            </p>
                            <p className="mt-1 text-xs text-zinc-500">
                                {task.assignedAgentId
                                    ? `Agent #${task.assignedAgentId}`
                                    : "Affectation requise"}
                            </p>
                        </div>
                    </div>
                </HmsCard>
                <HmsCard>
                    <div className="flex items-start gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-700">
                            <CalendarDaysIcon className="h-5 w-5" />
                        </div>
                        <div>
                            <p className="text-sm text-zinc-500">Date planifiée</p>
                            <p className="mt-1 text-lg font-semibold text-zinc-950">
                                <HousekeepingDate value={task.scheduledDate} />
                            </p>
                            <p className="mt-1 text-xs text-zinc-500">
                                Réservation {task.reservationId ? `#${task.reservationId}` : "non liée"}
                            </p>
                        </div>
                    </div>
                </HmsCard>
            </div>

            <HmsCard>
                <div className="grid gap-6 md:grid-cols-2">
                    <div>
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                            Statut et priorité
                        </p>
                        <div className="mt-3 flex flex-wrap gap-2">
                            <HousekeepingStatusBadge status={task.status} />
                            <PriorityBadge priority={task.priority} />
                            <TaskTypeBadge type={task.type} />
                        </div>
                    </div>
                    <div>
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                            Notes
                        </p>
                        <p className="mt-3 text-sm leading-6 text-zinc-700">
                            {task.notes || "Aucune note renseignée."}
                        </p>
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}

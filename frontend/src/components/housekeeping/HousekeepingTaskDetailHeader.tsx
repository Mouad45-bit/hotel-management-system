"use client";

import Link from "next/link";
import { ArrowLeftIcon, SparklesIcon } from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import { PriorityBadge } from "@/components/housekeeping/PriorityBadge";
import { TaskTypeBadge } from "@/components/housekeeping/TaskTypeBadge";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskDetailHeaderProps {
    task: HousekeepingTask;
}

export function HousekeepingTaskDetailHeader({
    task,
}: HousekeepingTaskDetailHeaderProps) {
    return (
        <HmsCard>
            <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                <div>
                    <Link
                        href="/housekeeping/tasks"
                        className="inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                    >
                        <ArrowLeftIcon className="h-4 w-4" />
                        Retour vers liste
                    </Link>
                    <div className="mt-5 flex items-center gap-3">
                        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-stone-900 text-white">
                            <SparklesIcon className="h-5 w-5" />
                        </div>
                        <div>
                            <h2 className="text-2xl font-semibold tracking-tight text-zinc-950">
                                Tâche #{task.id} · Chambre {task.roomNumber}
                            </h2>
                            <p className="mt-1 text-sm text-zinc-500">
                                {task.assignedAgentName
                                    ? `Assignée à ${task.assignedAgentName}`
                                    : "Tâche non assignée"}
                            </p>
                        </div>
                    </div>
                </div>
                <div className="flex flex-wrap gap-2">
                    <HousekeepingStatusBadge status={task.status} />
                    <PriorityBadge priority={task.priority} />
                    <TaskTypeBadge type={task.type} />
                </div>
            </div>
        </HmsCard>
    );
}

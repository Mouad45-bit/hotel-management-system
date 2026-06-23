"use client";

import Link from "next/link";
import { EyeIcon } from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import { PriorityBadge } from "@/components/housekeeping/PriorityBadge";
import { TaskTypeBadge } from "@/components/housekeeping/TaskTypeBadge";
import type { HousekeepingTask } from "@/types/housekeeping";

interface TodayHousekeepingTasksProps {
    title: string;
    description: string;
    tasks: HousekeepingTask[];
    loading?: boolean;
    emptyMessage: string;
}

export function TodayHousekeepingTasks({
    title,
    description,
    tasks,
    loading = false,
    emptyMessage,
}: TodayHousekeepingTasksProps) {
    return (
        <HmsCard className="p-0">
            <div className="border-b border-zinc-200 px-6 py-4">
                <h3 className="text-sm font-semibold text-zinc-950">{title}</h3>
                <p className="mt-1 text-sm text-zinc-500">{description}</p>
            </div>

            {loading && tasks.length === 0 ? (
                <div className="divide-y divide-zinc-100">
                    {Array.from({ length: 3 }).map((_, index) => (
                        <div key={index} className="grid gap-4 px-6 py-4 md:grid-cols-5">
                            {Array.from({ length: 5 }).map((__, cellIndex) => (
                                <div
                                    key={cellIndex}
                                    className="h-5 animate-pulse rounded-lg bg-zinc-100"
                                />
                            ))}
                        </div>
                    ))}
                </div>
            ) : tasks.length === 0 ? (
                <div className="flex min-h-40 items-center justify-center px-6 py-10 text-center">
                    <div>
                        <p className="text-sm font-medium text-zinc-900">
                            {emptyMessage}
                        </p>
                        <p className="mt-1 text-sm text-zinc-500">
                            Les tâches apparaîtront ici dès leur création.
                        </p>
                    </div>
                </div>
            ) : (
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-zinc-200">
                        <thead className="bg-zinc-50">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                    Chambre
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                    Type
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                    Agent
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                    État
                                </th>
                                <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                                    Action
                                </th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-100 bg-white">
                            {tasks.map((task) => (
                                <tr key={task.id} className="transition hover:bg-stone-50/60">
                                    <td className="whitespace-nowrap px-6 py-4">
                                        <p className="text-sm font-semibold text-zinc-950">
                                            Chambre {task.roomNumber}
                                        </p>
                                        <p className="mt-1 text-xs text-zinc-500">
                                            <HousekeepingDate
                                                value={task.scheduledDate}
                                                className="text-xs text-zinc-500"
                                            />
                                        </p>
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex flex-wrap gap-2">
                                            <TaskTypeBadge type={task.type} />
                                            <PriorityBadge priority={task.priority} />
                                        </div>
                                    </td>
                                    <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-700">
                                        {task.assignedAgentName ?? "Non assignée"}
                                    </td>
                                    <td className="whitespace-nowrap px-6 py-4">
                                        <HousekeepingStatusBadge status={task.status} />
                                    </td>
                                    <td className="whitespace-nowrap px-6 py-4 text-right">
                                        <Link
                                            href={`/housekeeping/tasks/${task.id}`}
                                            className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 transition hover:bg-zinc-50"
                                        >
                                            <EyeIcon className="h-4 w-4" />
                                            Voir
                                        </Link>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </HmsCard>
    );
}

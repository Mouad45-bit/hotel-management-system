"use client";

import Link from "next/link";
import { Eye, FileText, type LucideIcon } from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import { PriorityBadge } from "@/components/housekeeping/PriorityBadge";
import { TaskTypeBadge } from "@/components/housekeeping/TaskTypeBadge";
import { cn } from "@/lib/utils";
import type { HousekeepingTask } from "@/types/housekeeping";

interface TodayHousekeepingTasksProps {
    title: string;
    description: string;
    tasks: HousekeepingTask[];
    loading?: boolean;
    emptyMessage: string;
    icon?: LucideIcon;
    tone?: "default" | "info" | "warning";
    className?: string;
}

const TONE_CLASSES: Record<NonNullable<TodayHousekeepingTasksProps["tone"]>, string> = {
    default: "bg-zinc-100 text-zinc-700",
    info: "bg-blue-50 text-blue-700",
    warning: "bg-orange-50 text-orange-700",
};

export function TodayHousekeepingTasks({
    title,
    description,
    tasks,
    loading = false,
    emptyMessage,
    icon: Icon = FileText,
    tone = "default",
    className,
}: TodayHousekeepingTasksProps) {
    return (
        <HmsCard className={cn("overflow-hidden p-0", className)}>
            <div className="flex flex-col gap-3 border-b border-[var(--hms-soft-border)] px-4 py-5 sm:flex-row sm:items-start sm:justify-between xl:px-5">
                <div>
                    <h3 className="text-lg font-bold text-[var(--hms-text)]">
                        {title}
                    </h3>

                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                        {description}
                    </p>
                </div>

                <div
                    className={cn(
                        "flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl",
                        TONE_CLASSES[tone]
                    )}
                >
                    <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                </div>
            </div>

            {loading && tasks.length === 0 ? (
                <div className="divide-y divide-[var(--hms-soft-border)]">
                    {Array.from({ length: 3 }).map((_, index) => (
                        <div key={index} className="grid gap-3 px-4 py-4 md:grid-cols-5">
                            {Array.from({ length: 5 }).map((__, cellIndex) => (
                                <div
                                    key={cellIndex}
                                    className="h-5 animate-pulse rounded-lg bg-slate-100"
                                />
                            ))}
                        </div>
                    ))}
                </div>
            ) : tasks.length === 0 ? (
                <div className="flex min-h-56 items-center justify-center px-6 py-12 text-center">
                    <div>
                        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                            <Icon aria-hidden="true" className="h-6 w-6" strokeWidth={1.8} />
                        </div>

                        <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">
                            {emptyMessage}
                        </p>

                        <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                            Les tâches apparaîtront ici dès leur création.
                        </p>
                    </div>
                </div>
            ) : (
                <div className="divide-y divide-[var(--hms-soft-border)]">
                    {tasks.map((task) => (
                        <div
                            key={task.id}
                            className="grid gap-4 px-4 py-4 transition-colors hover:bg-slate-50 lg:grid-cols-[minmax(120px,0.9fr)_minmax(180px,1.3fr)_minmax(130px,1fr)_auto] lg:items-start xl:px-5"
                        >
                            <div className="min-w-0">
                                <p className="text-sm font-bold text-[var(--hms-text)]">
                                    Chambre {task.roomNumber}
                                </p>

                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                    <HousekeepingDate
                                        value={task.scheduledDate}
                                        className="text-xs text-[var(--hms-text-muted)]"
                                    />
                                </p>
                            </div>

                            <div className="flex min-w-0 flex-wrap gap-2">
                                <TaskTypeBadge type={task.type} />
                                <PriorityBadge priority={task.priority} />
                            </div>

                            <div className="min-w-0">
                                <p className="truncate text-sm font-semibold text-[var(--hms-text)]">
                                    {task.assignedAgentName ?? "Non assignée"}
                                </p>

                                <div className="mt-2">
                                    <HousekeepingStatusBadge status={task.status} />
                                </div>
                            </div>

                            <div className="flex justify-start lg:justify-end">
                                <Link
                                    href={`/housekeeping/tasks/${task.id}`}
                                    className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                    aria-label={`Voir la tâche ${task.id}`}
                                    title="Voir"
                                >
                                    <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                </Link>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </HmsCard>
    );
}

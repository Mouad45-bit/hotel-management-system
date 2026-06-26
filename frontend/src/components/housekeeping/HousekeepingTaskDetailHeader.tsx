"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskDetailHeaderProps {
    task: HousekeepingTask;
}

export function HousekeepingTaskDetailHeader({
    task,
}: HousekeepingTaskDetailHeaderProps) {
    return (
        <section className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
            <div className="min-w-0">
                <Link
                    href="/housekeeping/tasks"
                    className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    Retour aux tâches
                </Link>

                <p className="mt-6 text-xs font-bold uppercase tracking-[0.18em] text-[var(--hms-text-muted)]">
                    Tâche #{task.id}
                </p>

                <div className="mt-3 flex flex-wrap items-center gap-3">
                    <h2 className="text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                        Chambre {task.roomNumber}
                    </h2>

                    <HousekeepingStatusBadge status={task.status} />
                </div>

                <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                    Consultez les informations, les priorités et l’avancement de cette tâche.
                </p>
            </div>
        </section>
    );
}

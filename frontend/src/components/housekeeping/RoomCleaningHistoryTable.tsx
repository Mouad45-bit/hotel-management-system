"use client";

import Link from "next/link";
import { Eye, FileText } from "lucide-react";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import { PriorityBadge } from "@/components/housekeeping/PriorityBadge";
import { TaskTypeBadge } from "@/components/housekeeping/TaskTypeBadge";
import type { RoomCleaningHistoryItem } from "@/types/housekeeping";

interface RoomCleaningHistoryTableProps {
    history: RoomCleaningHistoryItem[];
    loading?: boolean;
}

export function RoomCleaningHistoryTable({
    history,
    loading = false,
}: RoomCleaningHistoryTableProps) {
    if (loading && history.length === 0) {
        return (
            <div className="divide-y divide-[var(--hms-soft-border)]">
                {Array.from({ length: 4 }).map((_, index) => (
                    <div key={index} className="grid gap-3 px-4 py-4 md:grid-cols-6">
                        {Array.from({ length: 6 }).map((__, cellIndex) => (
                            <div
                                key={cellIndex}
                                className="h-5 animate-pulse rounded-lg bg-slate-100"
                            />
                        ))}
                    </div>
                ))}
            </div>
        );
    }

    if (history.length === 0) {
        return (
            <div className="flex min-h-60 items-center justify-center px-6 py-12">
                <div className="text-center">
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <FileText aria-hidden="true" className="h-6 w-6" strokeWidth={1.8} />
                    </div>

                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">
                        Aucun historique pour cette chambre.
                    </p>
                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                        Les nettoyages apparaîtront après création de tâches.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-visible">
            <table className="w-full table-auto border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Date
                        </th>
                        <th className="border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Intervention
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Agent
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Durée
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Statut
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Action
                        </th>
                    </tr>
                </thead>
                <tbody className="bg-white">
                    {history.map((item) => (
                        <tr key={item.id} className="transition-colors hover:bg-slate-50">
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <HousekeepingDate value={item.scheduledDate} className="text-sm text-[var(--hms-text)]" />
                            </td>
                            <td className="border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <div className="flex flex-wrap gap-2">
                                    <TaskTypeBadge type={item.type} />
                                    <PriorityBadge priority={item.priority} />
                                </div>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top text-sm text-[var(--hms-text)]">
                                {item.assignedAgentName ?? "Non assignée"}
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top text-sm text-[var(--hms-text)]">
                                {item.durationMinutes
                                    ? `${item.durationMinutes} min`
                                    : "—"}
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center align-top">
                                <HousekeepingStatusBadge status={item.status} />
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right align-top">
                                <Link
                                    href={`/housekeeping/tasks/${item.id}`}
                                    className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                    aria-label={`Voir la tâche ${item.id}`}
                                    title="Voir"
                                >
                                    <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                </Link>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

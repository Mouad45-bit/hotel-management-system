"use client";

import Link from "next/link";
import { EyeIcon } from "@heroicons/react/24/outline";
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
            <div className="divide-y divide-zinc-100">
                {Array.from({ length: 4 }).map((_, index) => (
                    <div key={index} className="grid gap-4 px-6 py-4 md:grid-cols-6">
                        {Array.from({ length: 6 }).map((__, cellIndex) => (
                            <div
                                key={cellIndex}
                                className="h-5 animate-pulse rounded-lg bg-zinc-100"
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
                    <p className="text-sm font-medium text-zinc-900">
                        Aucun historique pour cette chambre.
                    </p>
                    <p className="mt-1 text-sm text-zinc-500">
                        Les nettoyages apparaîtront après création de tâches.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-zinc-200">
                <thead className="bg-zinc-50">
                    <tr>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Date
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Type
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Agent
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Durée
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Statut
                        </th>
                        <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Action
                        </th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100 bg-white">
                    {history.map((item) => (
                        <tr key={item.id} className="transition hover:bg-stone-50/60">
                            <td className="whitespace-nowrap px-6 py-4">
                                <HousekeepingDate value={item.scheduledDate} />
                            </td>
                            <td className="px-6 py-4">
                                <div className="flex flex-wrap gap-2">
                                    <TaskTypeBadge type={item.type} />
                                    <PriorityBadge priority={item.priority} />
                                </div>
                            </td>
                            <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-700">
                                {item.assignedAgentName ?? "Non assignée"}
                            </td>
                            <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-700">
                                {item.durationMinutes
                                    ? `${item.durationMinutes} min`
                                    : "—"}
                            </td>
                            <td className="whitespace-nowrap px-6 py-4">
                                <HousekeepingStatusBadge status={item.status} />
                            </td>
                            <td className="whitespace-nowrap px-6 py-4 text-right">
                                <Link
                                    href={`/housekeeping/tasks/${item.id}`}
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
    );
}

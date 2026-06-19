"use client";

import type { FormEvent } from "react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { PriorityBadge } from "@/components/housekeeping/PriorityBadge";
import { TaskTypeBadge } from "@/components/housekeeping/TaskTypeBadge";
import {
    HOUSEKEEPING_TASK_TYPES,
    HOUSEKEEPING_TYPE_LABELS,
    PRIORITIES,
    PRIORITY_LABELS,
    type HousekeepingAgentOption,
    type HousekeepingRoomOption,
    type HousekeepingTaskType,
    type Priority,
} from "@/types/housekeeping";

export interface HousekeepingTaskFormState {
    roomId: string;
    type: HousekeepingTaskType;
    priority: Priority;
    scheduledDate: string;
    assignedAgentId: string;
    notes: string;
}

interface HousekeepingTaskFormProps {
    form: HousekeepingTaskFormState;
    rooms: HousekeepingRoomOption[];
    agents: HousekeepingAgentOption[];
    errors?: Partial<Record<keyof HousekeepingTaskFormState, string>>;
    submitting?: boolean;
    onChange: <K extends keyof HousekeepingTaskFormState>(
        field: K,
        value: HousekeepingTaskFormState[K]
    ) => void;
    onSubmit: () => void;
}

export function HousekeepingTaskForm({
    form,
    rooms,
    agents,
    errors = {},
    submitting = false,
    onChange,
    onSubmit,
}: HousekeepingTaskFormProps) {
    function handleSubmit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        onSubmit();
    }

    const selectedRoom = rooms.find((room) => String(room.id) === form.roomId);
    const selectedAgent = agents.find(
        (agent) => String(agent.id) === form.assignedAgentId
    );

    return (
        <div className="grid gap-6 xl:grid-cols-[1fr_360px]">
            <HmsCard>
                <form onSubmit={handleSubmit} className="space-y-6">
                    <div className="grid gap-4 md:grid-cols-2">
                        <div>
                            <label className="text-xs font-medium text-zinc-600">
                                Chambre
                            </label>
                            <select
                                value={form.roomId}
                                onChange={(event) =>
                                    onChange("roomId", event.target.value)
                                }
                                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                            >
                                <option value="">Sélectionner une chambre</option>
                                {rooms.map((room) => (
                                    <option key={room.id} value={room.id}>
                                        Chambre {room.roomNumber} · {room.status}
                                    </option>
                                ))}
                            </select>
                            {errors.roomId && (
                                <p className="mt-1 text-xs text-red-600">
                                    {errors.roomId}
                                </p>
                            )}
                        </div>

                        <div>
                            <label className="text-xs font-medium text-zinc-600">
                                Type
                            </label>
                            <select
                                value={form.type}
                                onChange={(event) =>
                                    onChange(
                                        "type",
                                        event.target.value as HousekeepingTaskType
                                    )
                                }
                                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                            >
                                {HOUSEKEEPING_TASK_TYPES.map((type) => (
                                    <option key={type} value={type}>
                                        {HOUSEKEEPING_TYPE_LABELS[type]}
                                    </option>
                                ))}
                            </select>
                            {errors.type && (
                                <p className="mt-1 text-xs text-red-600">
                                    {errors.type}
                                </p>
                            )}
                        </div>

                        <div>
                            <label className="text-xs font-medium text-zinc-600">
                                Priorité
                            </label>
                            <select
                                value={form.priority}
                                onChange={(event) =>
                                    onChange("priority", event.target.value as Priority)
                                }
                                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                            >
                                {PRIORITIES.map((priority) => (
                                    <option key={priority} value={priority}>
                                        {PRIORITY_LABELS[priority]}
                                    </option>
                                ))}
                            </select>
                            {errors.priority && (
                                <p className="mt-1 text-xs text-red-600">
                                    {errors.priority}
                                </p>
                            )}
                        </div>

                        <div>
                            <label className="text-xs font-medium text-zinc-600">
                                Date planifiée
                            </label>
                            <input
                                type="date"
                                value={form.scheduledDate}
                                onChange={(event) =>
                                    onChange("scheduledDate", event.target.value)
                                }
                                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                            />
                            {errors.scheduledDate && (
                                <p className="mt-1 text-xs text-red-600">
                                    {errors.scheduledDate}
                                </p>
                            )}
                        </div>

                        <div className="md:col-span-2">
                            <label className="text-xs font-medium text-zinc-600">
                                Agent assigné optionnel
                            </label>
                            <select
                                value={form.assignedAgentId}
                                onChange={(event) =>
                                    onChange("assignedAgentId", event.target.value)
                                }
                                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                            >
                                <option value="">Non assignée</option>
                                {agents.map((agent) => (
                                    <option key={agent.id} value={agent.id}>
                                        {agent.fullName}
                                    </option>
                                ))}
                            </select>
                            {errors.assignedAgentId && (
                                <p className="mt-1 text-xs text-red-600">
                                    {errors.assignedAgentId}
                                </p>
                            )}
                        </div>

                        <div className="md:col-span-2">
                            <label className="text-xs font-medium text-zinc-600">
                                Notes
                            </label>
                            <textarea
                                value={form.notes}
                                onChange={(event) =>
                                    onChange("notes", event.target.value)
                                }
                                rows={5}
                                placeholder="Instructions particulières pour l’agent..."
                                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                            />
                            {errors.notes && (
                                <p className="mt-1 text-xs text-red-600">
                                    {errors.notes}
                                </p>
                            )}
                        </div>
                    </div>

                    <div className="flex justify-end">
                        <HmsButton type="submit" disabled={submitting}>
                            {submitting ? "Création..." : "Créer la tâche"}
                        </HmsButton>
                    </div>
                </form>
            </HmsCard>

            <HmsCard>
                <h3 className="text-sm font-semibold text-zinc-950">
                    Aperçu de la tâche
                </h3>
                <p className="mt-1 text-sm text-zinc-500">
                    La tâche sera créée au statut À faire.
                </p>

                <div className="mt-5 space-y-4">
                    <div className="rounded-2xl border border-zinc-200 p-4">
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                            Chambre
                        </p>
                        <p className="mt-1 text-sm font-semibold text-zinc-950">
                            {selectedRoom
                                ? `Chambre ${selectedRoom.roomNumber}`
                                : "Non sélectionnée"}
                        </p>
                        {selectedRoom && (
                            <p className="mt-1 text-xs text-zinc-500">
                                État actuel : {selectedRoom.status}
                            </p>
                        )}
                    </div>

                    <div className="flex flex-wrap gap-2">
                        <TaskTypeBadge type={form.type} />
                        <PriorityBadge priority={form.priority} />
                    </div>

                    <div className="rounded-2xl border border-zinc-200 p-4">
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                            Agent
                        </p>
                        <p className="mt-1 text-sm font-semibold text-zinc-950">
                            {selectedAgent?.fullName ?? "Non assignée"}
                        </p>
                    </div>

                    <div className="rounded-2xl border border-stone-200 bg-stone-50 p-4 text-sm text-stone-700">
                        Une chambre en nettoyage ne doit pas être vendue comme disponible. La terminaison pourra remettre la chambre en AVAILABLE.
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}

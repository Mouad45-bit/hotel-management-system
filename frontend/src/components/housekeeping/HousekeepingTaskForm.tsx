"use client";

import type { FormEvent } from "react";
import Link from "next/link";
import { ClipboardList, Sparkles } from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HmsInput, HmsSelect, HmsTextarea } from "@/components/hms/HmsField";
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
        <form onSubmit={handleSubmit} className="space-y-6">
            <div className="grid gap-6 xl:grid-cols-2">
                <HmsCard className="p-6">
                    <div>
                        <h3 className="text-lg font-bold text-[var(--hms-text)]">
                            Paramètres de la tâche
                        </h3>

                        <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                            Renseignez les informations nécessaires à la planification.
                        </p>
                    </div>

                    <div className="mt-6 grid gap-5 md:grid-cols-2">
                        <HmsSelect
                            id="housekeeping-create-room"
                            label="Chambre"
                            value={form.roomId}
                            onChange={(event) =>
                                onChange("roomId", event.target.value)
                            }
                            error={errors.roomId}
                        >
                            <option value="">Sélectionner une chambre</option>
                            {rooms.map((room) => (
                                <option key={room.id} value={room.id}>
                                    Chambre {room.roomNumber} · {room.status}
                                </option>
                            ))}
                        </HmsSelect>

                        <HmsSelect
                            id="housekeeping-create-type"
                            label="Type"
                            value={form.type}
                            onChange={(event) =>
                                onChange(
                                    "type",
                                    event.target.value as HousekeepingTaskType
                                )
                            }
                            error={errors.type}
                        >
                            {HOUSEKEEPING_TASK_TYPES.map((type) => (
                                <option key={type} value={type}>
                                    {HOUSEKEEPING_TYPE_LABELS[type]}
                                </option>
                            ))}
                        </HmsSelect>

                        <HmsSelect
                            id="housekeeping-create-priority"
                            label="Priorité"
                            value={form.priority}
                            onChange={(event) =>
                                onChange("priority", event.target.value as Priority)
                            }
                            error={errors.priority}
                        >
                            {PRIORITIES.map((priority) => (
                                <option key={priority} value={priority}>
                                    {PRIORITY_LABELS[priority]}
                                </option>
                            ))}
                        </HmsSelect>

                        <HmsInput
                            id="housekeeping-create-date"
                            label="Date planifiée"
                            type="date"
                            value={form.scheduledDate}
                            onChange={(event) =>
                                onChange("scheduledDate", event.target.value)
                            }
                            error={errors.scheduledDate}
                        />

                        <HmsSelect
                            id="housekeeping-create-agent"
                            label="Agent"
                            className="md:col-span-2"
                            value={form.assignedAgentId}
                            onChange={(event) =>
                                onChange("assignedAgentId", event.target.value)
                            }
                            error={errors.assignedAgentId}
                        >
                            <option value="">Non assignée</option>
                            {agents.map((agent) => (
                                <option key={agent.id} value={agent.id}>
                                    {agent.fullName}
                                </option>
                            ))}
                        </HmsSelect>

                        <HmsTextarea
                            id="housekeeping-create-notes"
                            label="Notes"
                            className="md:col-span-2"
                            value={form.notes}
                            onChange={(event) =>
                                onChange("notes", event.target.value)
                            }
                            rows={5}
                            placeholder="Instructions particulières pour l’agent..."
                            error={errors.notes}
                        />
                    </div>
                </HmsCard>

                <HmsCard className="p-6">
                    <h3 className="text-lg font-bold text-[var(--hms-text)]">
                        Aperçu métier
                    </h3>

                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                        Vérifiez le contexte avant de créer la tâche au statut À faire.
                    </p>

                    <div className="mt-6 space-y-5">
                        <dl className="grid gap-4 rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 sm:grid-cols-2">
                            <div>
                                <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">
                                    Chambre
                                </dt>
                                <dd className="mt-1 text-sm font-bold text-[var(--hms-text)]">
                                    {selectedRoom
                                        ? `Chambre ${selectedRoom.roomNumber}`
                                        : "Non sélectionnée"}
                                </dd>
                            </div>

                            <div>
                                <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">
                                    État actuel
                                </dt>
                                <dd className="mt-1 text-sm font-semibold text-[var(--hms-text)]">
                                    {selectedRoom?.status ?? "—"}
                                </dd>
                            </div>

                            <div className="sm:col-span-2">
                                <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">
                                    Agent
                                </dt>
                                <dd className="mt-1 text-sm font-semibold text-[var(--hms-text)]">
                                    {selectedAgent?.fullName ?? "Non assignée"}
                                </dd>
                            </div>
                        </dl>

                        <div className="flex flex-wrap gap-2">
                            <TaskTypeBadge type={form.type} />
                            <PriorityBadge priority={form.priority} />
                        </div>

                        <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm leading-6 text-[var(--hms-text-muted)]">
                            Une chambre en nettoyage ne doit pas être vendue comme disponible. La tâche pourra remettre la chambre en disponibilité une fois terminée.
                        </div>
                    </div>
                </HmsCard>
            </div>

            <HmsCard className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3 text-sm text-[var(--hms-text-muted)]">
                    <ClipboardList aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    {selectedRoom
                        ? `Chambre ${selectedRoom.roomNumber} sélectionnée`
                        : "Sélectionnez une chambre pour créer la tâche"}
                </div>

                <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                    <Link
                        href="/housekeeping/tasks"
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        Annuler
                    </Link>

                    <HmsButton type="submit" disabled={submitting}>
                        <Sparkles aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                        {submitting ? "Création..." : "Créer la tâche"}
                    </HmsButton>
                </div>
            </HmsCard>
        </form>
    );
}

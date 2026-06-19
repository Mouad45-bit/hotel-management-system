"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
    ArrowLeftIcon,
    ClipboardDocumentListIcon,
    ExclamationTriangleIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import {
    HousekeepingTaskForm,
    type HousekeepingTaskFormState,
} from "@/components/housekeeping/HousekeepingTaskForm";
import {
    createHousekeepingTask,
    getHousekeepingAgents,
    getHousekeepingRooms,
} from "@/services/housekeepingApi";
import { createHousekeepingTaskSchema } from "@/schemas/housekeeping.schema";
import type {
    HousekeepingAgentOption,
    HousekeepingRoomOption,
} from "@/types/housekeeping";

const DEFAULT_FORM: HousekeepingTaskFormState = {
    roomId: "",
    type: "STANDARD_CLEANING",
    priority: "MEDIUM",
    scheduledDate: "2026-06-19",
    assignedAgentId: "",
    notes: "",
};

type FieldErrors = Partial<Record<keyof HousekeepingTaskFormState, string>>;

function extractErrors(issues: { path: PropertyKey[]; message: string }[]) {
    const errors: FieldErrors = {};

    issues.forEach((issue) => {
        const field = issue.path[0];

        if (typeof field === "string") {
            errors[field as keyof HousekeepingTaskFormState] = issue.message;
        }
    });

    return errors;
}

export function HousekeepingTaskCreateClient() {
    const router = useRouter();
    const [form, setForm] = useState<HousekeepingTaskFormState>(DEFAULT_FORM);
    const [rooms, setRooms] = useState<HousekeepingRoomOption[]>([]);
    const [agents, setAgents] = useState<HousekeepingAgentOption[]>([]);
    const [errors, setErrors] = useState<FieldErrors>({});
    const [isLoading, setIsLoading] = useState(true);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadOptions() {
        setIsLoading(true);
        setErrorMessage(null);

        try {
            const [roomOptions, agentOptions] = await Promise.all([
                getHousekeepingRooms(),
                getHousekeepingAgents(),
            ]);

            setRooms(roomOptions);
            setAgents(agentOptions);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger les options de création."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        void loadOptions();
    }, []);

    function updateField<K extends keyof HousekeepingTaskFormState>(
        field: K,
        value: HousekeepingTaskFormState[K]
    ) {
        setForm((current) => ({
            ...current,
            [field]: value,
        }));
    }

    async function handleSubmit() {
        setErrorMessage(null);

        const validationResult = createHousekeepingTaskSchema.safeParse({
            roomId: form.roomId,
            type: form.type,
            priority: form.priority,
            scheduledDate: form.scheduledDate,
            assignedAgentId: form.assignedAgentId,
            notes: form.notes,
        });

        if (!validationResult.success) {
            setErrors(extractErrors(validationResult.error.issues));
            return;
        }

        setErrors({});
        setIsSubmitting(true);

        try {
            const createdTask = await createHousekeepingTask(validationResult.data);
            router.push(`/housekeeping/tasks/${createdTask.id}`);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de créer la tâche housekeeping."
            );
        } finally {
            setIsSubmitting(false);
        }
    }

    return (
        <div className="space-y-6">
            <HmsCard>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div>
                        <Link
                            href="/housekeeping/tasks"
                            className="inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                        >
                            <ArrowLeftIcon className="h-4 w-4" />
                            Retour aux tâches
                        </Link>
                        <div className="mt-5 flex items-center gap-3">
                            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-stone-900 text-white">
                                <ClipboardDocumentListIcon className="h-5 w-5" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-semibold tracking-tight text-zinc-950">
                                    Création manuelle
                                </h2>
                                <p className="mt-1 text-sm text-zinc-500">
                                    Créez une tâche TODO liée à une chambre existante.
                                </p>
                            </div>
                        </div>
                    </div>
                    <div className="rounded-2xl border border-stone-200 bg-stone-50 px-4 py-3 text-sm text-stone-700">
                        <p className="font-semibold">Règle V1</p>
                        <p className="mt-1">
                            La création manuelle est réservée aux managers ou administrateurs.
                        </p>
                    </div>
                </div>
            </HmsCard>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />
                    <div>
                        <p className="font-semibold">Erreur</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            {isLoading ? (
                <HmsCard>
                    <div className="h-80 animate-pulse rounded-xl bg-zinc-100" />
                </HmsCard>
            ) : (
                <HousekeepingTaskForm
                    form={form}
                    rooms={rooms}
                    agents={agents}
                    errors={errors}
                    submitting={isSubmitting}
                    onChange={updateField}
                    onSubmit={handleSubmit}
                />
            )}
        </div>
    );
}

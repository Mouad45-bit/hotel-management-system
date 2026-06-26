"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
    ArrowLeft,
    TriangleAlert,
} from "lucide-react";
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
        const timeoutId = window.setTimeout(() => {
            void loadOptions();
        }, 0);

        return () => window.clearTimeout(timeoutId);
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
        <div className="space-y-8">
            <section>
                <Link
                    href="/housekeeping/tasks"
                    className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    Retour aux tâches
                </Link>

                <h2 className="mt-6 text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                    Créer une tâche
                </h2>

                <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                    Planifiez une intervention housekeeping,
                    <br className="hidden md:block" /> choisissez la chambre, la priorité et l’agent si l’affectation est déjà connue.
                </p>
            </section>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Erreur</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            {isLoading ? (
                <HmsCard>
                    <div className="h-80 animate-pulse rounded-xl bg-slate-100" />
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

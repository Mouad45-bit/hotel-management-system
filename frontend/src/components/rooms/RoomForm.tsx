"use client";

import { useState, type FormEvent } from "react";
import { AlertCircle } from "lucide-react";
import { roomSchema, type RoomFormValues } from "@/schemas/room.schema";
import type { RoomType } from "@/types/room";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsInput, HmsSelect, HmsTextarea } from "@/components/hms/HmsField";
import { HmsCard } from "@/components/hms/HmsCard";

const TYPE_OPTIONS: Record<RoomType, string> = {
    SINGLE: "Single", DOUBLE: "Double", TWIN: "Twin",
    SUITE: "Suite", FAMILY: "Family", DELUXE: "Deluxe",
};

interface RoomFormProps {
    initialData?: Partial<RoomFormValues>;
    onSubmit: (data: RoomFormValues) => Promise<void>;
    onCancel: () => void;
    isLoading?: boolean;
    submitLabel?: string;
}

export function RoomForm({ initialData, onSubmit, onCancel, isLoading, submitLabel = "Créer" }: RoomFormProps) {
    const [formData, setFormData] = useState<Partial<RoomFormValues>>(
        initialData ?? {
            type: "DOUBLE",
            active: true,
            status: "AVAILABLE",
            number: "",
            description: "",
        }
    );
    const [errors, setErrors] = useState<Record<string, string>>({});

    const handleChange = (field: keyof RoomFormValues, value: string | number | boolean) => {
        setFormData((prev) => ({ ...prev, [field]: value }));
        if (errors[field]) setErrors((prev) => ({ ...prev, [field]: "" }));
    };

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setErrors({});

        const validation = roomSchema.safeParse(formData);
        if (!validation.success) {
            const formattedErrors: Record<string, string> = {};
            validation.error.issues.forEach((issue) => {
                formattedErrors[String(issue.path[0])] = issue.message;
            });
            setErrors(formattedErrors);
            return;
        }

        try {
            await onSubmit(validation.data);
        } catch (err) {
            setErrors({ global: err instanceof Error ? err.message : "Erreur inattendue" });
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            {errors.global && (
                <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                    <AlertCircle className="h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <span className="text-sm font-medium">{errors.global}</span>
                </div>
            )}

            <HmsCard>
                <h2 className="text-lg font-bold text-[var(--hms-text)]">Informations générales</h2>

                <div className="mt-6 grid grid-cols-1 gap-x-6 gap-y-5 md:grid-cols-2">
                    <HmsInput
                        id="number"
                        label="Numéro de chambre *"
                        type="text"
                        placeholder="Exemple : 101"
                        value={String(formData.number ?? "")}
                        onChange={(e) => handleChange("number", e.target.value)}
                        error={errors.number}
                    />
                    <HmsSelect
                        id="type"
                        label="Type de chambre *"
                        value={formData.type ?? ""}
                        onChange={(e) => handleChange("type", e.target.value)}
                    >
                        {(Object.keys(TYPE_OPTIONS) as RoomType[]).map((t) => (
                            <option key={t} value={t}>{TYPE_OPTIONS[t]}</option>
                        ))}
                    </HmsSelect>
                    <HmsInput
                        id="floor"
                        label="Étage *"
                        type="number"
                        min={0}
                        placeholder="Exemple : 1"
                        value={String(formData.floor ?? "")}
                        onChange={(e) => handleChange("floor", Number(e.target.value))}
                        error={errors.floor}
                    />
                    <HmsInput
                        id="capacity"
                        label="Capacité *"
                        type="number"
                        min={1}
                        placeholder="Exemple : 2"
                        value={String(formData.capacity ?? "")}
                        onChange={(e) => handleChange("capacity", Number(e.target.value))}
                        error={errors.capacity}
                    />
                    <HmsInput
                        id="pricePerNight"
                        label="Prix par nuit *"
                        type="number"
                        min={0}
                        step="0.01"
                        placeholder="Exemple : 500"
                        value={String(formData.pricePerNight ?? "")}
                        onChange={(e) => handleChange("pricePerNight", Number(e.target.value))}
                        error={errors.pricePerNight}
                    />
                    <HmsSelect
                        id="active"
                        label="Activation administrative *"
                        value={formData.active === false ? "false" : "true"}
                        onChange={(e) => handleChange("active", e.target.value === "true")}
                    >
                        <option value="true">Active</option>
                        <option value="false">Inactive</option>
                    </HmsSelect>
                </div>

                <div className="mt-5">
                    <HmsTextarea
                        id="description"
                        label="Description"
                        rows={4}
                        placeholder="Décrivez brièvement la chambre..."
                        value={formData.description ?? ""}
                        onChange={(e) => handleChange("description", e.target.value)}
                    />
                </div>
            </HmsCard>

            <div className="flex justify-end gap-3">
                <HmsButton type="button" variant="secondary" onClick={onCancel} disabled={isLoading}>
                    Annuler
                </HmsButton>
                <HmsButton type="submit" disabled={isLoading}>
                    {isLoading ? "Enregistrement..." : submitLabel}
                </HmsButton>
            </div>
        </form>
    );
}

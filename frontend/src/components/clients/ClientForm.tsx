"use client";

import { useState, type FormEvent } from "react";
import { AlertCircle } from "lucide-react";
import { clientSchema, type ClientFormValues } from "@/schemas/client.schema";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsInput, HmsTextarea } from "@/components/hms/HmsField";
import { HmsCard } from "@/components/hms/HmsCard";

interface ClientFormProps {
    initialData?: Partial<ClientFormValues>;
    onSubmit: (data: ClientFormValues) => Promise<void>;
    onCancel: () => void;
    isLoading?: boolean;
    submitLabel?: string;
}

export function ClientForm({ initialData, onSubmit, onCancel, isLoading, submitLabel = "Créer" }: ClientFormProps) {
    const [formData, setFormData] = useState<Partial<ClientFormValues>>(
        initialData ?? {
            firstName: "",
            lastName: "",
            email: "",
            phone: "",
            cin: "",
            passportNumber: "",
            nationality: "",
            address: "",
            birthDate: "",
        }
    );
    const [errors, setErrors] = useState<Record<string, string>>({});

    const handleChange = (field: keyof ClientFormValues, value: string) => {
        setFormData((prev) => ({ ...prev, [field]: value }));
        if (errors[field]) setErrors((prev) => ({ ...prev, [field]: "" }));
    };

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setErrors({});

        const validation = clientSchema.safeParse(formData);
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
                <h2 className="text-lg font-bold text-[var(--hms-text)]">Informations personnelles</h2>

                <div className="mt-6 grid grid-cols-1 gap-x-6 gap-y-5 md:grid-cols-2">
                    <HmsInput
                        id="firstName"
                        label="Prénom *"
                        type="text"
                        placeholder="Exemple : Mohamed"
                        value={formData.firstName ?? ""}
                        onChange={(e) => handleChange("firstName", e.target.value)}
                        error={errors.firstName}
                    />
                    <HmsInput
                        id="lastName"
                        label="Nom *"
                        type="text"
                        placeholder="Exemple : Alaoui"
                        value={formData.lastName ?? ""}
                        onChange={(e) => handleChange("lastName", e.target.value)}
                        error={errors.lastName}
                    />
                    <HmsInput
                        id="email"
                        label="Email"
                        type="email"
                        placeholder="Exemple : client@email.com"
                        value={formData.email ?? ""}
                        onChange={(e) => handleChange("email", e.target.value)}
                        error={errors.email}
                    />
                    <HmsInput
                        id="phone"
                        label="Téléphone"
                        type="tel"
                        placeholder="Exemple : +212 6XX XXX XXX"
                        value={formData.phone ?? ""}
                        onChange={(e) => handleChange("phone", e.target.value)}
                        error={errors.phone}
                    />
                    <HmsInput
                        id="cin"
                        label="CIN"
                        type="text"
                        placeholder="Exemple : AB123456"
                        value={formData.cin ?? ""}
                        onChange={(e) => handleChange("cin", e.target.value)}
                        error={errors.cin}
                    />
                    <HmsInput
                        id="passportNumber"
                        label="Numéro de passeport"
                        type="text"
                        placeholder="Exemple : AA1234567"
                        value={formData.passportNumber ?? ""}
                        onChange={(e) => handleChange("passportNumber", e.target.value)}
                        error={errors.passportNumber}
                    />
                    <HmsInput
                        id="nationality"
                        label="Nationalité"
                        type="text"
                        placeholder="Exemple : Marocaine"
                        value={formData.nationality ?? ""}
                        onChange={(e) => handleChange("nationality", e.target.value)}
                    />
                    <HmsInput
                        id="birthDate"
                        label="Date de naissance"
                        type="date"
                        value={formData.birthDate ?? ""}
                        onChange={(e) => handleChange("birthDate", e.target.value)}
                        error={errors.birthDate}
                    />
                </div>

                <div className="mt-5">
                    <HmsTextarea
                        id="address"
                        label="Adresse"
                        rows={3}
                        placeholder="Adresse complète du client..."
                        value={formData.address ?? ""}
                        onChange={(e) => handleChange("address", e.target.value)}
                    />
                </div>

                <p className="mt-4 text-xs text-[var(--hms-text-muted)]">
                    <span className="font-medium">*</span> Au moins un moyen d&apos;identification est requis : email, CIN, passeport ou téléphone.
                </p>
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

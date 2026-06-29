"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { AuthService } from "@/services/auth.service";
import { AlertCircle } from "lucide-react";

const ROLES = [
    { value: "ADMIN", label: "Admin" },
    { value: "MANAGER", label: "Manager" },
    { value: "RECEPTIONIST", label: "Réceptionniste" },
    { value: "HOUSEKEEPING_AGENT", label: "Agent Housekeeping" },
];

export default function CreateUserPage() {
    const router = useRouter();
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState("");
    const [form, setForm] = useState({ username: "", email: "", password: "", firstName: "", lastName: "", role: "RECEPTIONIST" });

    const set = (field: string, value: string) => setForm((prev) => ({ ...prev, [field]: value }));

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setError("");
        setIsLoading(true);
        try {
            await AuthService.createUser(form);
            router.push("/users");
        } catch (err) {
            setError(err instanceof Error ? err.message : "Erreur");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <AppLayout>
            <PageHeader
                backHref="/users"
                eyebrow="Création"
                title="Nouvel utilisateur"
                description="Créez un nouveau compte utilisateur avec un rôle et des identifiants de connexion."
            />

            <form onSubmit={handleSubmit} className="space-y-6">
                {error && (
                    <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                        <AlertCircle className="h-5 w-5 shrink-0" strokeWidth={1.8} />
                        <span className="text-sm font-medium">{error}</span>
                    </div>
                )}

                <HmsCard>
                    <h2 className="text-lg font-bold text-[var(--hms-text)]">Informations du compte</h2>

                    <div className="mt-6 grid grid-cols-1 gap-x-6 gap-y-5 md:grid-cols-2">
                        <HmsInput id="firstName" label="Prénom *" type="text" required value={form.firstName} onChange={(e) => set("firstName", e.target.value)} />
                        <HmsInput id="lastName" label="Nom *" type="text" required value={form.lastName} onChange={(e) => set("lastName", e.target.value)} />
                        <HmsInput id="username" label="Nom d'utilisateur *" type="text" required value={form.username} onChange={(e) => set("username", e.target.value)} placeholder="ex: jdupont" />
                        <HmsInput id="email" label="Email" type="email" value={form.email} onChange={(e) => set("email", e.target.value)} />
                        <HmsInput id="password" label="Mot de passe *" type="password" required minLength={6} value={form.password} onChange={(e) => set("password", e.target.value)} />
                        <HmsSelect id="role" label="Rôle *" value={form.role} onChange={(e) => set("role", e.target.value)}>
                            {ROLES.map((r) => (
                                <option key={r.value} value={r.value}>{r.label}</option>
                            ))}
                        </HmsSelect>
                    </div>
                </HmsCard>

                <div className="flex justify-end gap-3">
                    <HmsButton type="button" variant="secondary" onClick={() => router.push("/users")} disabled={isLoading}>
                        Annuler
                    </HmsButton>
                    <HmsButton type="submit" disabled={isLoading}>
                        {isLoading ? "Création..." : "Créer l'utilisateur"}
                    </HmsButton>
                </div>
            </form>
        </AppLayout>
    );
}

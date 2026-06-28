"use client";

import { useEffect, useState, type FormEvent } from "react";
import { useParams, useRouter } from "next/navigation";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { UserRoleBadge } from "@/components/users/UserRoleBadge";
import { AuthService } from "@/services/auth.service";
import { getEmployees, activateEmployee, deactivateEmployee } from "@/services/staffApi";
import type { User } from "@/types/user";
import type { Employee } from "@/types/staff";
import { RefreshCcw, AlertCircle, Power, Check } from "lucide-react";

const ROLES = [
    { value: "ADMIN", label: "Admin" },
    { value: "MANAGER", label: "Manager" },
    { value: "RECEPTIONIST", label: "Réceptionniste" },
    { value: "HOUSEKEEPING_AGENT", label: "Agent Housekeeping" },
    { value: "HR", label: "Ressources Humaines" },
];

export default function EditUserPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [user, setUser] = useState<User | null>(null);
    const [linkedEmployee, setLinkedEmployee] = useState<Employee | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isSaving, setIsSaving] = useState(false);
    const [form, setForm] = useState({ email: "", firstName: "", lastName: "", role: "" });

    const fetchData = () => {
        setLoading(true);
        Promise.all([
            AuthService.getUserById(id),
            getEmployees({ page: 0, size: 1000 }),
        ])
            .then(([u, employeesPage]) => {
                setUser(u);
                setForm({ email: u.email ?? "", firstName: u.firstName, lastName: u.lastName, role: u.role });
                const emp = employeesPage.content.find((e) => e.authUserId === u.id) ?? null;
                setLinkedEmployee(emp);
            })
            .catch((err) => setError(err instanceof Error ? err.message : "Utilisateur introuvable"))
            .finally(() => setLoading(false));
    };

    useEffect(() => { fetchData(); }, [id]);

    const set = (field: string, value: string) => setForm((prev) => ({ ...prev, [field]: value }));

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setIsSaving(true);
        try {
            await AuthService.updateUser(id, form);
            router.push("/users");
        } catch (err) {
            setError(err instanceof Error ? err.message : "Erreur");
        } finally {
            setIsSaving(false);
        }
    };

    const handleToggleActive = async () => {
        if (!user) return;
        try {
            if (user.active) {
                await AuthService.deactivateUser(id);
                if (linkedEmployee) {
                    await deactivateEmployee(linkedEmployee.id).catch(() => {});
                }
            } else {
                await AuthService.activateUser(id);
                if (linkedEmployee) {
                    await activateEmployee(linkedEmployee.id).catch(() => {});
                }
            }
            fetchData();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur");
        }
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-[var(--hms-text-muted)]">
                    <RefreshCcw className="mr-2 h-4 w-4 animate-spin" strokeWidth={1.8} />
                    Chargement...
                </div>
            </AppLayout>
        );
    }

    if (error && !user) {
        return (
            <AppLayout>
                <HmsCard>
                    <div className="flex items-start gap-4">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" strokeWidth={1.8} />
                        <p className="font-semibold text-red-700">{error}</p>
                    </div>
                </HmsCard>
            </AppLayout>
        );
    }

    return (
        <AppLayout>
            <PageHeader
                backHref="/users"
                eyebrow={`@${user?.username}`}
                title={`${user?.firstName} ${user?.lastName}`}
                description={linkedEmployee
                    ? `Employé lié : ${linkedEmployee.fullName} (CIN ${linkedEmployee.cin})`
                    : "Ce compte n'est lié à aucun employé."
                }
                actions={
                    <HmsButton
                        variant={user?.active ? "danger" : "primary"}
                        onClick={handleToggleActive}
                    >
                        {user?.active ? (
                            <>
                                <Power className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Désactiver
                            </>
                        ) : (
                            <>
                                <Check className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Activer
                            </>
                        )}
                    </HmsButton>
                }
            />

            <form onSubmit={handleSubmit} className="space-y-6">
                {error && (
                    <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                        <AlertCircle className="h-5 w-5 shrink-0" strokeWidth={1.8} />
                        <span className="text-sm font-medium">{error}</span>
                    </div>
                )}

                <HmsCard>
                    <div className="mb-6 flex items-center justify-between">
                        <h2 className="text-lg font-bold text-[var(--hms-text)]">Informations</h2>
                        {user && <UserRoleBadge role={user.role} />}
                    </div>

                    <div className="grid grid-cols-1 gap-x-6 gap-y-5 md:grid-cols-2">
                        <HmsInput id="firstName" label="Prénom" type="text" value={form.firstName} onChange={(e) => set("firstName", e.target.value)} />
                        <HmsInput id="lastName" label="Nom" type="text" value={form.lastName} onChange={(e) => set("lastName", e.target.value)} />
                        <HmsInput id="email" label="Email" type="email" value={form.email} onChange={(e) => set("email", e.target.value)} />
                        <HmsSelect id="role" label="Rôle" value={form.role} onChange={(e) => set("role", e.target.value)}>
                            {ROLES.map((r) => (
                                <option key={r.value} value={r.value}>{r.label}</option>
                            ))}
                        </HmsSelect>
                    </div>
                </HmsCard>

                <div className="flex justify-end gap-3">
                    <HmsButton type="button" variant="secondary" onClick={() => router.push("/users")} disabled={isSaving}>
                        Annuler
                    </HmsButton>
                    <HmsButton type="submit" disabled={isSaving}>
                        {isSaving ? "Enregistrement..." : "Enregistrer"}
                    </HmsButton>
                </div>
            </form>
        </AppLayout>
    );
}

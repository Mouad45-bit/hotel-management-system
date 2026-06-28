"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsCard } from "@/components/hms/HmsCard";
import { UserRoleBadge } from "@/components/users/UserRoleBadge";
import { ClientStatusBadge } from "@/components/clients/ClientStatusBadge";
import { AuthService } from "@/services/auth.service";
import { getEmployees } from "@/services/staffApi";
import type { User } from "@/types/user";
import type { Employee } from "@/types/staff";
import { RefreshCcw, AlertCircle, Eye, Users } from "lucide-react";

interface LinkedUser {
    user: User;
    employee: Employee;
}

export default function UsersPage() {
    const [linkedUsers, setLinkedUsers] = useState<LinkedUser[]>([]);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        Promise.all([
            AuthService.getUsers(),
            getEmployees({ page: 0, size: 1000 }),
        ])
            .then(([users, employeesPage]) => {
                const userMap = new Map<number, User>();
                for (const u of users) userMap.set(u.id, u);

                const linked: LinkedUser[] = [];
                for (const emp of employeesPage.content) {
                    if (emp.authUserId && userMap.has(emp.authUserId)) {
                        linked.push({ user: userMap.get(emp.authUserId)!, employee: emp });
                    }
                }
                linked.sort((a, b) => a.user.lastName.localeCompare(b.user.lastName));
                setLinkedUsers(linked);
            })
            .catch((err) => setError(err instanceof Error ? err.message : "Erreur"))
            .finally(() => setLoading(false));
    }, []);

    return (
        <AppLayout>
            <PageHeader
                title="Comptes système"
                description="Utilisateurs du logiciel liés à un employé. La gestion des comptes se fait principalement depuis le module Personnel."
            />

            {error ? (
                <HmsCard>
                    <div className="flex items-start gap-4">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" strokeWidth={1.8} />
                        <div>
                            <p className="font-semibold text-red-700">Impossible de charger les utilisateurs</p>
                            <p className="mt-1 text-sm text-red-600">{error}</p>
                        </div>
                    </div>
                </HmsCard>
            ) : isLoading ? (
                <HmsCard>
                    <div className="flex items-center justify-center py-12 text-[var(--hms-text-muted)]">
                        <RefreshCcw className="mr-2 h-4 w-4 animate-spin" strokeWidth={1.8} />
                        Chargement...
                    </div>
                </HmsCard>
            ) : (
                <HmsCard className="overflow-hidden p-0">
                    <div className="overflow-x-auto">
                        <table className="w-full table-auto border-collapse">
                            <thead className="bg-slate-50">
                                <tr>
                                    {["Utilisateur", "Employé", "Rôle", "Statut"].map((h) => (
                                        <th key={h} className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">{h}</th>
                                    ))}
                                    <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white">
                                {linkedUsers.length === 0 ? (
                                    <tr>
                                        <td colSpan={5} className="px-6 py-12 text-center">
                                            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                                                <Users className="h-6 w-6" strokeWidth={1.8} />
                                            </div>
                                            <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">Aucun compte système lié</p>
                                            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                                                Liez un compte depuis le module Personnel.
                                            </p>
                                        </td>
                                    </tr>
                                ) : linkedUsers.map(({ user: u, employee: emp }) => (
                                    <tr key={u.id} className="transition-colors hover:bg-slate-50">
                                        <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                            <p className="text-sm font-bold text-[var(--hms-text)]">@{u.username}</p>
                                            <p className="text-xs text-[var(--hms-text-muted)]">{u.email ?? "—"}</p>
                                        </td>
                                        <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                            <p className="text-sm font-bold text-[var(--hms-text)]">{emp.fullName}</p>
                                            <p className="text-xs text-[var(--hms-text-muted)]">CIN {emp.cin}</p>
                                        </td>
                                        <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                            <UserRoleBadge role={u.role} />
                                        </td>
                                        <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                            <ClientStatusBadge active={u.active} />
                                        </td>
                                        <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right">
                                            <Link
                                                href={`/staff/${emp.id}`}
                                                className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                                title="Voir l'employé"
                                            >
                                                <Eye className="h-4 w-4" strokeWidth={1.8} />
                                            </Link>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </HmsCard>
            )}
        </AppLayout>
    );
}

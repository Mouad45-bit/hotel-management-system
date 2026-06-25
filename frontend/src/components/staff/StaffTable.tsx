"use client";

import Link from "next/link";
import { Eye, Pencil, Power, UserRound } from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { DepartmentBadge, StaffStatusBadge } from "@/components/staff/StaffBadges";
import type { Employee } from "@/types/staff";

interface StaffTableProps {
    employees: Employee[];
    loading?: boolean;
    emptyMessage?: string;
    onToggleActive: (employee: Employee) => void;
}

export function StaffTable({
    employees,
    loading = false,
    emptyMessage = "Aucun employé trouvé.",
    onToggleActive,
}: StaffTableProps) {
    if (loading && employees.length === 0) {
        return (
            <div className="divide-y divide-[var(--hms-soft-border)]">
                {Array.from({ length: 5 }).map((_, index) => (
                    <div key={index} className="grid gap-3 px-4 py-4 md:grid-cols-6">
                        {Array.from({ length: 6 }).map((__, cellIndex) => (
                            <div key={cellIndex} className="h-5 animate-pulse rounded-lg bg-slate-100" />
                        ))}
                    </div>
                ))}
            </div>
        );
    }

    if (employees.length === 0) {
        return (
            <div className="flex min-h-60 items-center justify-center px-6 py-12">
                <div className="text-center">
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <UserRound aria-hidden="true" className="h-6 w-6" strokeWidth={1.8} />
                    </div>
                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">{emptyMessage}</p>
                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                        Modifiez les filtres ou ajoutez un employé.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-visible">
            <table className="w-full table-auto border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Employé
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Département
                        </th>
                        <th className="border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Contact
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Compte utilisateur
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Statut
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Actions
                        </th>
                    </tr>
                </thead>
                <tbody className="bg-white">
                    {employees.map((employee) => (
                        <tr key={employee.id} className="transition-colors hover:bg-slate-50">
                            <td className="border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm font-bold text-[var(--hms-text)]">{employee.fullName}</p>
                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">CIN {employee.cin}</p>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <DepartmentBadge department={employee.department} />
                            </td>
                            <td className="border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm text-[var(--hms-text)]">{employee.email ?? "Email non renseigné"}</p>
                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">{employee.phone ?? "Téléphone non renseigné"}</p>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm font-semibold text-[var(--hms-text)]">
                                    {employee.authUserId ? "Lié" : "Non lié"}
                                </p>
                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                    {employee.authUserId ? `Utilisateur #${employee.authUserId}` : "Aucun compte Auth"}
                                </p>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center align-top">
                                <StaffStatusBadge active={employee.active} />
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right align-top">
                                <div className="flex justify-end gap-1.5">
                                    <Link
                                        href={`/staff/${employee.id}`}
                                        className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        aria-label={`Voir ${employee.fullName}`}
                                        title="Voir"
                                    >
                                        <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>
                                    <Link
                                        href={`/staff/${employee.id}/edit`}
                                        className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        aria-label={`Modifier ${employee.fullName}`}
                                        title="Modifier"
                                    >
                                        <Pencil aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>
                                    <HmsButton
                                        type="button"
                                        variant="icon"
                                        className={employee.active ? "h-9 min-h-9 w-9 text-red-600 hover:text-red-700" : "h-9 min-h-9 w-9"}
                                        onClick={() => onToggleActive(employee)}
                                        aria-label={employee.active ? `Désactiver ${employee.fullName}` : `Activer ${employee.fullName}`}
                                        title={employee.active ? "Désactiver" : "Activer"}
                                    >
                                        <Power aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    </HmsButton>
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowLeft,
    CircleCheckBig,
    Pencil,
    TriangleAlert,
    UserRoundX,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { DepartmentBadge, StaffStatusBadge } from "@/components/staff/StaffBadges";
import { StaffActionModal } from "@/components/staff/StaffActionModal";
import { StaffDate } from "@/components/staff/StaffDate";
import {
    activateEmployee,
    deactivateEmployee,
    getEmployeeById,
} from "@/services/staffApi";
import type { Employee } from "@/types/staff";

interface StaffDetailClientProps {
    employeeId: number;
}

type ModalType = "activate" | "deactivate" | null;

interface TimelineItem {
    label: string;
    date?: string | null;
    description: string;
}

export function StaffDetailClient({ employeeId }: StaffDetailClientProps) {
    const [employee, setEmployee] = useState<Employee | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [modalType, setModalType] = useState<ModalType>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [actionError, setActionError] = useState<string | null>(null);

    async function loadEmployee() {
        if (!Number.isFinite(employeeId) || employeeId <= 0) {
            setEmployee(null);
            setErrorMessage("Identifiant employé invalide.");
            setIsLoading(false);
            return;
        }

        setIsLoading(true);
        setErrorMessage(null);

        try {
            const loadedEmployee = await getEmployeeById(employeeId);
            setEmployee(loadedEmployee);
        } catch (error) {
            setErrorMessage(error instanceof Error ? error.message : "Impossible de charger l’employé.");
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            void loadEmployee();
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, [employeeId]);

    function openModal(type: ModalType) {
        setModalType(type);
        setActionError(null);
    }

    async function handleConfirmAction() {
        if (!employee || !modalType) {
            return;
        }

        setIsSubmitting(true);
        setActionError(null);

        try {
            let updatedEmployee: Employee;

            if (modalType === "activate") {
                updatedEmployee = await activateEmployee(employee.id);
            } else {
                updatedEmployee = await deactivateEmployee(employee.id);
            }

            setEmployee(updatedEmployee);
            setModalType(null);
        } catch (error) {
            setActionError(error instanceof Error ? error.message : "Action impossible.");
        } finally {
            setIsSubmitting(false);
        }
    }

    if (isLoading) {
        return (
            <div className="space-y-8">
                <HmsCard>
                    <div className="h-6 w-48 animate-pulse rounded-lg bg-slate-100" />
                    <div className="mt-4 h-10 w-80 animate-pulse rounded-lg bg-slate-100" />
                </HmsCard>
                <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
                    <HmsCard><div className="h-72 animate-pulse rounded-xl bg-slate-100" /></HmsCard>
                    <HmsCard><div className="h-72 animate-pulse rounded-xl bg-slate-100" /></HmsCard>
                </div>
            </div>
        );
    }

    if (errorMessage || !employee) {
        return (
            <div className="space-y-6">
                <Link
                    href="/staff"
                    className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    Retour au personnel
                </Link>
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Employé introuvable</p>
                        <p className="mt-1">{errorMessage ?? "Impossible d’afficher cet employé."}</p>
                    </div>
                </div>
            </div>
        );
    }

    const hasSystemAccount = Boolean(employee.authUserId);

    const timelineItems: TimelineItem[] = [
        {
            label: "Création",
            date: employee.createdAt,
            description: "La fiche employé a été créée.",
        },
        {
            label: "Dernière mise à jour",
            date: employee.updatedAt,
            description: "Les informations disponibles ont été modifiées.",
        },
    ];

    return (
        <div className="space-y-8">
            <section className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
                <div className="min-w-0">
                    <Link
                        href="/staff"
                        className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                        Retour au personnel
                    </Link>

                    <p className="mt-6 text-xs font-bold uppercase tracking-[0.18em] text-[var(--hms-text-muted)]">
                        Employé #{employee.id}
                    </p>

                    <div className="mt-3 flex flex-wrap items-center gap-3">
                        <h2 className="text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                            {employee.fullName}
                        </h2>
                        <DepartmentBadge department={employee.department} />
                    </div>

                    <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                        Fiche opérationnelle du personnel : identité, département et coordonnées.
                    </p>
                </div>

                <Link
                    href={`/staff/${employee.id}/edit`}
                    className="inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <Pencil aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    Modifier
                </Link>
            </section>

            <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
                <div className="min-w-0 space-y-6">
                    <HmsCard className="p-6">
                        <h3 className="text-lg font-bold text-[var(--hms-text)]">Informations principales</h3>
                        <dl className="mt-5 grid gap-4 sm:grid-cols-2">
                            <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">Identité</dt>
                                <dd className="mt-1 text-sm font-bold text-[var(--hms-text)]">{employee.fullName}</dd>
                            </div>
                            <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">CIN</dt>
                                <dd className="mt-1 text-sm font-bold text-[var(--hms-text)]">{employee.cin}</dd>
                            </div>
                            <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">Département</dt>
                                <dd className="mt-2"><DepartmentBadge department={employee.department} /></dd>
                            </div>
                            {hasSystemAccount && (
                                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                                    <dt className="text-xs font-semibold text-[var(--hms-text-muted)]">Statut</dt>
                                    <dd className="mt-2"><StaffStatusBadge active={employee.active} /></dd>
                                </div>
                            )}
                        </dl>
                    </HmsCard>

                    <HmsCard className="p-6">
                        <h3 className="text-lg font-bold text-[var(--hms-text)]">Coordonnées</h3>
                        <dl className="mt-5 space-y-3 text-sm">
                            <div className="flex justify-between gap-4 border-b border-[var(--hms-soft-border)] py-3">
                                <dt className="text-[var(--hms-text-muted)]">Email</dt>
                                <dd className="font-semibold text-[var(--hms-text)]">{employee.email ?? "Non renseigné"}</dd>
                            </div>
                            <div className="flex justify-between gap-4 py-3">
                                <dt className="text-[var(--hms-text-muted)]">Téléphone</dt>
                                <dd className="font-semibold text-[var(--hms-text)]">{employee.phone ?? "Non renseigné"}</dd>
                            </div>
                        </dl>
                    </HmsCard>

                    {hasSystemAccount && (
                        <HmsCard className="p-6">
                            <h3 className="text-lg font-bold text-[var(--hms-text)]">Actions métier</h3>
                            <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                                L’activation et la désactivation sont des actions dédiées.
                            </p>
                            <div className="mt-5">
                                {employee.active ? (
                                    <HmsButton type="button" variant="danger" onClick={() => openModal("deactivate")}>
                                        <UserRoundX aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                        Désactiver l’employé
                                    </HmsButton>
                                ) : (
                                    <HmsButton type="button" onClick={() => openModal("activate")}>
                                        <CircleCheckBig aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                        Activer l’employé
                                    </HmsButton>
                                )}
                            </div>
                        </HmsCard>
                    )}
                </div>

                <div className="min-w-0 space-y-6">
                    <HmsCard className="p-6">
                        <h3 className="text-lg font-bold text-[var(--hms-text)]">Historique</h3>
                        <p className="mt-1 text-sm text-[var(--hms-text-muted)]">Dates réellement disponibles sur la fiche.</p>
                        <div className="mt-6">
                            {timelineItems.map((item, index) => {
                                const isLast = index === timelineItems.length - 1;
                                return (
                                    <div key={item.label} className="flex gap-3 pb-5 last:pb-0">
                                        <div className="relative flex w-4 shrink-0 justify-center">
                                            <div className="relative z-10 mt-1 h-3 w-3 rounded-full bg-emerald-600 ring-4 ring-emerald-50" />
                                            {!isLast && <div className="absolute bottom-[-4px] top-4 w-px bg-emerald-200" />}
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <p className="text-sm font-semibold text-[var(--hms-text)]">{item.label}</p>
                                            <p className="mt-1"><StaffDate value={item.date} withTime className="text-xs text-[var(--hms-text-muted)]" /></p>
                                            <p className="mt-1 text-xs leading-5 text-[var(--hms-text-muted)]">{item.description}</p>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </HmsCard>
                </div>
            </div>

            <StaffActionModal
                open={modalType === "deactivate"}
                title="Désactiver l’employé"
                description="Un employé désactivé ne peut plus être affecté à une tâche housekeeping. Aucune donnée n’est supprimée."
                icon={UserRoundX}
                iconClassName="bg-red-50 text-red-700"
                confirmLabel="Désactiver l’employé"
                danger
                submitting={isSubmitting}
                onClose={() => openModal(null)}
                onConfirm={() => void handleConfirmAction()}
            >
                <p className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm text-[var(--hms-text-muted)]">
                    {employee.fullName} restera consultable dans le personnel.
                </p>
                {actionError && <p className="mt-3 text-sm text-red-600">{actionError}</p>}
            </StaffActionModal>

            <StaffActionModal
                open={modalType === "activate"}
                title="Activer l’employé"
                description="Les données de l’employé sont conservées et son statut redevient opérationnel."
                icon={CircleCheckBig}
                iconClassName="bg-emerald-50 text-emerald-700"
                confirmLabel="Activer l’employé"
                submitting={isSubmitting}
                onClose={() => openModal(null)}
                onConfirm={() => void handleConfirmAction()}
            >
                <p className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm text-[var(--hms-text-muted)]">
                    {employee.fullName} pourra de nouveau être utilisé dans les opérations.
                </p>
                {actionError && <p className="mt-3 text-sm text-red-600">{actionError}</p>}
            </StaffActionModal>
        </div>
    );
}

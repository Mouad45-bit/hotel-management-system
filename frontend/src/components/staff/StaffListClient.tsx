"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Plus, RefreshCw, TriangleAlert, UserRoundX, CircleCheckBig, Trash2 } from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { PageHeader } from "@/components/layout/PageHeader";
import { StaffActionModal } from "@/components/staff/StaffActionModal";
import { StaffFilters } from "@/components/staff/StaffFilters";
import { StaffStatsCards } from "@/components/staff/StaffStatsCards";
import { StaffTable } from "@/components/staff/StaffTable";
import {
    activateEmployee,
    deleteEmployee,
    deactivateEmployee,
    getEmployees,
    getStaffStats,
} from "@/services/staffApi";
import { AuthService } from "@/services/auth.service";
import {
    staffFiltersSchema,
    toStaffSearchParams,
    type StaffFiltersFormValues,
} from "@/schemas/staff.schema";
import {
    type DepartmentFilter,
    type Employee,
    type PageResponse,
    type StaffFiltersState,
    type StaffStats,
} from "@/types/staff";
import { extractFormErrors } from "@/lib/formErrors";

const PAGE_SIZE = 8;

const EMPTY_STATS: StaffStats = {
    total: 0,
    active: 0,
    inactive: 0,
    housekeeping: 0,
    linked: 0,
};

interface ReadableSearchParams {
    get: (name: string) => string | null;
}

function readFilters(searchParams: ReadableSearchParams): StaffFiltersState {
    const active = searchParams.get("active");
    const department = searchParams.get("department");

    return {
        keyword: searchParams.get("keyword") ?? "",
        department: department ? (department as DepartmentFilter) : "ALL",
        active:
            active === "true"
                ? "ACTIVE"
                : active === "false"
                  ? "INACTIVE"
                  : "ALL",
    };
}

export function StaffListClient() {
    const router = useRouter();
    const pathname = usePathname();
    const searchParams = useSearchParams();

    const [filters, setFilters] = useState<StaffFiltersState>(() => readFilters(searchParams));
    const [filterErrors, setFilterErrors] = useState<Partial<Record<keyof StaffFiltersState, string>>>({});
    const [pageResponse, setPageResponse] = useState<PageResponse<Employee> | null>(null);
    const [stats, setStats] = useState<StaffStats>(EMPTY_STATS);
    const [currentPage, setCurrentPage] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [selectedEmployee, setSelectedEmployee] = useState<Employee | null>(null);
    const [employeeToDelete, setEmployeeToDelete] = useState<Employee | null>(null);
    const [isActionSubmitting, setIsActionSubmitting] = useState(false);
    const [isDeleteSubmitting, setIsDeleteSubmitting] = useState(false);
    const [actionError, setActionError] = useState<string | null>(null);
    const [deleteError, setDeleteError] = useState<string | null>(null);
    const [usernameMap, setUsernameMap] = useState<Record<number, string>>({});

    function updateUrl(nextFilters: StaffFiltersState, page: number) {
        const validationResult = staffFiltersSchema.safeParse(nextFilters);

        if (!validationResult.success) {
            return;
        }

        const params = toStaffSearchParams(validationResult.data as StaffFiltersFormValues);
        const query = new URLSearchParams();

        Object.entries({ ...params, page }).forEach(([key, value]) => {
            if (value !== undefined && value !== null && value !== "") {
                query.set(key, String(value));
            }
        });

        router.replace(query.toString() ? `${pathname}?${query}` : pathname, { scroll: false });
    }

    async function loadEmployees(nextFilters: StaffFiltersState, page: number) {
        const validationResult = staffFiltersSchema.safeParse(nextFilters);

        if (!validationResult.success) {
            setFilterErrors(extractFormErrors<keyof StaffFiltersState>(validationResult.error.issues));
            return;
        }

        setIsLoading(true);
        setErrorMessage(null);
        setFilterErrors({});

        try {
            const search = toStaffSearchParams(validationResult.data as StaffFiltersFormValues);
            const [employeesPage, staffStats, allUsers] = await Promise.all([
                getEmployees({ ...search, page, size: PAGE_SIZE, sort: "lastName,asc" }),
                getStaffStats(),
                AuthService.getUsers().catch(() => []),
            ]);

            const uMap: Record<number, string> = {};
            for (const u of allUsers) { uMap[u.id] = u.username; }
            setUsernameMap(uMap);

            setPageResponse(employeesPage);
            setStats(staffStats);
            setCurrentPage(employeesPage.page);
            updateUrl(nextFilters, employeesPage.page);
        } catch (error) {
            setErrorMessage(error instanceof Error ? error.message : "Impossible de charger le personnel.");
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        const initialFilters = readFilters(searchParams);
        const page = Number(searchParams.get("page") ?? 0);

        const timeoutId = window.setTimeout(() => {
            void loadEmployees(initialFilters, Number.isFinite(page) && page > 0 ? page : 0);
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, []);

    function handleApplyFilters(nextFilters: StaffFiltersState) {
        setFilters(nextFilters);
        void loadEmployees(nextFilters, 0);
    }

    function handlePreviousPage() {
        if (currentPage === 0) {
            return;
        }

        void loadEmployees(filters, currentPage - 1);
    }

    function handleNextPage() {
        if (!pageResponse || pageResponse.last) {
            return;
        }

        void loadEmployees(filters, currentPage + 1);
    }

    async function handleConfirmToggleActive() {
        if (!selectedEmployee) {
            return;
        }

        setIsActionSubmitting(true);
        setActionError(null);

        try {
            if (selectedEmployee.active) {
                await deactivateEmployee(selectedEmployee.id);
                if (selectedEmployee.authUserId) {
                    await AuthService.deactivateUser(selectedEmployee.authUserId).catch(() => {});
                }
            } else {
                await activateEmployee(selectedEmployee.id);
                if (selectedEmployee.authUserId) {
                    await AuthService.activateUser(selectedEmployee.authUserId).catch(() => {});
                }
            }

            setSelectedEmployee(null);
            await loadEmployees(filters, currentPage);
        } catch (error) {
            setActionError(error instanceof Error ? error.message : "Action impossible.");
        } finally {
            setIsActionSubmitting(false);
        }
    }

    async function handleConfirmDelete() {
        if (!employeeToDelete) {
            return;
        }

        setIsDeleteSubmitting(true);
        setDeleteError(null);

        try {
            await deleteEmployee(employeeToDelete.id);
            if (employeeToDelete.authUserId) {
                await AuthService.deactivateUser(employeeToDelete.authUserId).catch(() => {});
            }

            setEmployeeToDelete(null);
            await loadEmployees(filters, currentPage);
        } catch (error) {
            setDeleteError(error instanceof Error ? error.message : "Suppression impossible.");
        } finally {
            setIsDeleteSubmitting(false);
        }
    }

    const employees = pageResponse?.content ?? [];

    return (
        <div className="space-y-8">
            <PageHeader
                title="Personnel"
                description="Gestion des employés et de leur statut opérationnel."
                actions={
                    <Link href="/staff/create">
                        <HmsButton>
                            <Plus aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                            Ajouter un employé
                        </HmsButton>
                    </Link>
                }
            />

            <StaffStatsCards stats={stats} loading={isLoading} />

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Erreur de chargement</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <HmsCard className="overflow-hidden p-0">
                <div className="flex flex-col gap-2 border-b border-[var(--hms-soft-border)] px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between">
                    <p className="text-sm font-semibold text-[var(--hms-text-muted)]">
                        {pageResponse ? `${pageResponse.totalElements} employé${pageResponse.totalElements > 1 ? "s" : ""} trouvé${pageResponse.totalElements > 1 ? "s" : ""}` : "Chargement du personnel"}
                    </p>

                    <div className="flex items-center gap-1.5">
                        <HmsButton type="button" variant="secondary" onClick={() => void loadEmployees(filters, currentPage)} disabled={isLoading}>
                            <RefreshCw aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                            Actualiser
                        </HmsButton>
                        <StaffFilters
                            filters={filters}
                            errors={filterErrors}
                            onApply={handleApplyFilters}
                        />
                    </div>
                </div>

                <StaffTable
                    employees={employees}
                    loading={isLoading}
                    emptyMessage="Aucun employé ne correspond aux filtres."
                    usernameMap={usernameMap}
                    onToggleActive={setSelectedEmployee}
                    onDelete={setEmployeeToDelete}
                />

                <div className="flex items-center justify-between border-t border-[var(--hms-soft-border)] px-6 py-5">
                    <p className="text-sm text-[var(--hms-text-muted)]">
                        Page <span className="font-medium text-[var(--hms-text)]">{pageResponse ? pageResponse.page + 1 : 1}</span> sur <span className="font-medium text-[var(--hms-text)]">{pageResponse?.totalPages || 1}</span>
                    </p>
                    <div className="flex items-center gap-2">
                        <HmsButton type="button" variant="secondary" onClick={handlePreviousPage} disabled={isLoading || currentPage === 0} className="min-h-10 px-3">
                            Précédent
                        </HmsButton>
                        <HmsButton type="button" variant="secondary" onClick={handleNextPage} disabled={isLoading || !pageResponse || pageResponse.last} className="min-h-10 px-3">
                            Suivant
                        </HmsButton>
                    </div>
                </div>
            </HmsCard>

            <StaffActionModal
                open={Boolean(selectedEmployee)}
                title={selectedEmployee?.active ? "Désactiver l’employé" : "Activer l’employé"}
                description={selectedEmployee?.active ? "Un employé désactivé ne peut plus être affecté à une tâche housekeeping." : "L’employé redevient disponible pour les opérations de l’hôtel."}
                icon={selectedEmployee?.active ? UserRoundX : CircleCheckBig}
                iconClassName={selectedEmployee?.active ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"}
                confirmLabel={selectedEmployee?.active ? "Désactiver l’employé" : "Activer l’employé"}
                danger={selectedEmployee?.active}
                submitting={isActionSubmitting}
                onClose={() => setSelectedEmployee(null)}
                onConfirm={() => void handleConfirmToggleActive()}
            >
                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm text-[var(--hms-text-muted)]">
                    {selectedEmployee ? `${selectedEmployee.fullName} restera dans l’historique du personnel.` : ""}
                </div>
                {actionError && <p className="mt-3 text-sm text-red-600">{actionError}</p>}
            </StaffActionModal>

            <StaffActionModal
                open={Boolean(employeeToDelete)}
                title="Supprimer l’employé"
                description="Cette action retire l’employé des listes du personnel. Les données techniques restent conservées côté système."
                icon={Trash2}
                iconClassName="bg-red-50 text-red-700"
                confirmLabel="Supprimer l’employé"
                danger
                submitting={isDeleteSubmitting}
                onClose={() => setEmployeeToDelete(null)}
                onConfirm={() => void handleConfirmDelete()}
            >
                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm text-[var(--hms-text-muted)]">
                    {employeeToDelete ? `${employeeToDelete.fullName} ne sera plus affiché dans la liste du personnel.` : ""}
                </div>
                {deleteError && <p className="mt-3 text-sm text-red-600">{deleteError}</p>}
            </StaffActionModal>
        </div>
    );
}

export const DEPARTMENTS = [
    "RECEPTION",
    "HOUSEKEEPING",
    "MANAGEMENT",
    "HR",
    "MAINTENANCE",
    "SECURITY",
    "KITCHEN",
] as const;

export type Department = (typeof DEPARTMENTS)[number];

export type DepartmentFilter = Department | "ALL";

export type ActiveStatusFilter = "ALL" | "ACTIVE" | "INACTIVE";

export interface Employee {
    id: number;
    firstName: string;
    lastName: string;
    fullName: string;
    email?: string | null;
    phone?: string | null;
    cin: string;
    department: Department;
    active: boolean;
    authUserId?: number | null;
    createdAt: string;
    updatedAt: string;
}

export interface CreateEmployeeRequest {
    firstName: string;
    lastName: string;
    email?: string;
    phone?: string;
    cin: string;
    department: Department;
}

export type UpdateEmployeeRequest = CreateEmployeeRequest;

export interface LinkAuthUserRequest {
    userId: number;
}

export interface StaffSearchParams {
    keyword?: string;
    department?: Department;
    active?: boolean;
    page?: number;
    size?: number;
    sort?: string;
}

export interface StaffFiltersState {
    keyword: string;
    department: DepartmentFilter;
    active: ActiveStatusFilter;
}

export interface StaffStats {
    total: number;
    active: number;
    inactive: number;
    housekeeping: number;
    linked: number;
}

export interface PageResponse<T> {
    content: T[];
    page: number;
    size: number;
    totalElements: number;
    totalPages: number;
    last: boolean;
}

export const DEPARTMENT_LABELS: Record<Department, string> = {
    RECEPTION: "Réception",
    HOUSEKEEPING: "Housekeeping",
    MANAGEMENT: "Management",
    HR: "RH",
    MAINTENANCE: "Maintenance",
    SECURITY: "Sécurité",
    KITCHEN: "Cuisine",
};

export const DEPARTMENT_FILTER_LABELS: Record<DepartmentFilter, string> = {
    ALL: "Tous les départements",
    ...DEPARTMENT_LABELS,
};

export const ACTIVE_STATUS_FILTER_LABELS: Record<ActiveStatusFilter, string> = {
    ALL: "Tous les statuts",
    ACTIVE: "Actifs",
    INACTIVE: "Désactivés",
};

export const DEPARTMENT_BADGE_CLASSES: Record<Department, string> = {
    RECEPTION: "bg-blue-50 text-blue-700 ring-blue-200",
    HOUSEKEEPING: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    MANAGEMENT: "bg-purple-50 text-purple-700 ring-purple-200",
    HR: "bg-pink-50 text-pink-700 ring-pink-200",
    MAINTENANCE: "bg-amber-50 text-amber-700 ring-amber-200",
    SECURITY: "bg-zinc-100 text-zinc-700 ring-zinc-200",
    KITCHEN: "bg-orange-50 text-orange-700 ring-orange-200",
};

export const DEFAULT_STAFF_FILTERS: StaffFiltersState = {
    keyword: "",
    department: "ALL",
    active: "ALL",
};

export function formatEmployeeCount(count: number): string {
    return `${count} employé${count > 1 ? "s" : ""}`;
}

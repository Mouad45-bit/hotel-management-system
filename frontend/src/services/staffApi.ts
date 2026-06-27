import { apiFetch } from "@/lib/api";
import type {
    CreateEmployeeRequest,
    Employee,
    LinkAuthUserRequest,
    PageResponse,
    StaffSearchParams,
    StaffStats,
    UpdateEmployeeRequest,
} from "@/types/staff";

function buildQueryString(params: StaffSearchParams): string {
    const searchParams = new URLSearchParams();

    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== "") {
            searchParams.set(key, String(value));
        }
    });

    const queryString = searchParams.toString();

    return queryString ? `?${queryString}` : "";
}

export async function getEmployees(
    params: StaffSearchParams = {}
): Promise<PageResponse<Employee>> {
    const queryString = buildQueryString(params);

    return apiFetch<PageResponse<Employee>>(`/api/employees${queryString}`);
}

export async function getStaffStats(): Promise<StaffStats> {
    const employeesPage = await getEmployees({
        page: 0,
        size: 1000,
        sort: "lastName,asc",
    });

    const employees = employeesPage.content;

    return {
        total: employees.length,
        active: employees.filter((e) => e.active).length,
        inactive: employees.filter((e) => !e.active).length,
        housekeeping: employees.filter(
            (e) => e.department === "HOUSEKEEPING" && e.active
        ).length,
        linked: employees.filter((e) => Boolean(e.authUserId)).length,
    };
}

export async function getEmployeeById(id: number): Promise<Employee> {
    return apiFetch<Employee>(`/api/employees/${id}`);
}

export async function createEmployee(
    request: CreateEmployeeRequest
): Promise<Employee> {
    return apiFetch<Employee>("/api/employees", {
        method: "POST",
        body: JSON.stringify(request),
    });
}

export async function updateEmployee(
    id: number,
    request: UpdateEmployeeRequest
): Promise<Employee> {
    return apiFetch<Employee>(`/api/employees/${id}`, {
        method: "PUT",
        body: JSON.stringify(request),
    });
}

export async function deactivateEmployee(id: number): Promise<Employee> {
    return apiFetch<Employee>(`/api/employees/${id}/deactivate`, {
        method: "PATCH",
    });
}

export async function activateEmployee(id: number): Promise<Employee> {
    return apiFetch<Employee>(`/api/employees/${id}/activate`, {
        method: "PATCH",
    });
}

export async function linkAuthUser(
    id: number,
    request: LinkAuthUserRequest
): Promise<Employee> {
    return apiFetch<Employee>(`/api/employees/${id}/link-user`, {
        method: "PATCH",
        body: JSON.stringify(request),
    });
}

export async function unlinkAuthUser(id: number): Promise<Employee> {
    return apiFetch<Employee>(`/api/employees/${id}/unlink-user`, {
        method: "PATCH",
    });
}

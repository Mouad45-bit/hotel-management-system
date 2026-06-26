import { mockEmployees } from "@/mocks/staff";
import type {
    CreateEmployeeRequest,
    Employee,
    LinkAuthUserRequest,
    PageResponse,
    StaffSearchParams,
    StaffStats,
    UpdateEmployeeRequest,
} from "@/types/staff";

const API_BASE_URL =
    process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

const USE_MOCK_API = process.env.NEXT_PUBLIC_USE_STAFF_MOCKS !== "false";

const MOCK_DELAY_MS = 150;

let employeeStore: Employee[] = mockEmployees.map(clone);

function clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value)) as T;
}

function mockResponse<T>(value: T): Promise<T> {
    return new Promise((resolve) => {
        setTimeout(() => resolve(clone(value)), MOCK_DELAY_MS);
    });
}

function nowIsoDateTime(): string {
    return new Date().toISOString().slice(0, 19);
}

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

async function staffFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    const response = await fetch(`${API_BASE_URL}${path}`, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(options.headers ?? {}),
        },
    });

    if (!response.ok) {
        let message = `Requête impossible (${response.status}).`;

        try {
            const payload = await response.json() as { message?: string; error?: string };
            message = payload.message ?? payload.error ?? message;
        } catch {
            // Keep the safe generic message when the backend returns no JSON body.
        }

        throw new Error(message);
    }

    if (response.status === 204) {
        return undefined as T;
    }

    return response.json() as Promise<T>;
}

function getEmployeeOrThrow(id: number): Employee {
    const employee = employeeStore.find((item) => item.id === id);

    if (!employee) {
        throw new Error(`Employé introuvable avec l'identifiant ${id}.`);
    }

    return employee;
}

function getNextEmployeeId(): number {
    return Math.max(0, ...employeeStore.map((employee) => employee.id)) + 1;
}

function assertUniqueCin(cin: string, employeeId?: number) {
    const duplicated = employeeStore.some(
        (employee) => employee.cin.toLowerCase() === cin.toLowerCase() && employee.id !== employeeId
    );

    if (duplicated) {
        throw new Error("Un employé existe déjà avec ce CIN.");
    }
}

function assertUniqueEmail(email?: string, employeeId?: number) {
    if (!email) {
        return;
    }

    const duplicated = employeeStore.some(
        (employee) =>
            employee.email?.toLowerCase() === email.toLowerCase() && employee.id !== employeeId
    );

    if (duplicated) {
        throw new Error("Un employé existe déjà avec cet email.");
    }
}

function assertAuthUserAvailable(userId: number, employeeId: number) {
    const linkedEmployee = employeeStore.find(
        (employee) => employee.authUserId === userId && employee.id !== employeeId
    );

    if (linkedEmployee) {
        throw new Error("Ce compte utilisateur est déjà lié à un autre employé.");
    }
}

function createPageResponse<T>(content: T[], page: number, size: number): PageResponse<T> {
    const startIndex = page * size;
    const paginatedContent = content.slice(startIndex, startIndex + size);

    return {
        content: paginatedContent,
        page,
        size,
        totalElements: content.length,
        totalPages: Math.ceil(content.length / size),
        last: startIndex + size >= content.length,
    };
}

function filterEmployees(params: StaffSearchParams): Employee[] {
    return employeeStore.filter((employee) => {
        const keyword = params.keyword?.trim().toLowerCase();
        const matchesKeyword = !keyword || [
            employee.firstName,
            employee.lastName,
            employee.fullName,
            employee.email ?? "",
            employee.phone ?? "",
            employee.cin,
        ].some((value) => value.toLowerCase().includes(keyword));

        const matchesDepartment = !params.department || employee.department === params.department;
        const matchesActive = params.active === undefined || employee.active === params.active;

        return matchesKeyword && matchesDepartment && matchesActive;
    });
}

function sortEmployees(employees: Employee[], sort?: string): Employee[] {
    const [field = "lastName", direction = "asc"] = (sort || "lastName,asc").split(",");
    const sortedEmployees = [...employees].sort((first, second) => {
        const firstValue = first[field as keyof Employee];
        const secondValue = second[field as keyof Employee];

        if (typeof firstValue === "number" && typeof secondValue === "number") {
            return firstValue - secondValue;
        }

        return String(firstValue ?? "").localeCompare(String(secondValue ?? ""));
    });

    return direction === "desc" ? sortedEmployees.reverse() : sortedEmployees;
}

function calculateStats(employees: Employee[]): StaffStats {
    return {
        total: employees.length,
        active: employees.filter((employee) => employee.active).length,
        inactive: employees.filter((employee) => !employee.active).length,
        housekeeping: employees.filter((employee) => employee.department === "HOUSEKEEPING" && employee.active).length,
        linked: employees.filter((employee) => Boolean(employee.authUserId)).length,
    };
}

export async function getEmployees(params: StaffSearchParams = {}): Promise<PageResponse<Employee>> {
    if (!USE_MOCK_API) {
        const queryString = buildQueryString(params);

        return staffFetch<PageResponse<Employee>>(`/api/employees${queryString}`);
    }

    const page = params.page ?? 0;
    const size = params.size ?? 20;
    const filteredEmployees = filterEmployees(params);
    const sortedEmployees = sortEmployees(filteredEmployees, params.sort);

    return mockResponse(createPageResponse(sortedEmployees, page, size));
}

export async function getStaffStats(): Promise<StaffStats> {
    if (!USE_MOCK_API) {
        const employeesPage = await getEmployees({ page: 0, size: 1000, sort: "lastName,asc" });

        return calculateStats(employeesPage.content);
    }

    return mockResponse(calculateStats(employeeStore));
}

export async function getEmployeeById(id: number): Promise<Employee> {
    if (!USE_MOCK_API) {
        return staffFetch<Employee>(`/api/employees/${id}`);
    }

    return mockResponse(getEmployeeOrThrow(id));
}

export async function createEmployee(request: CreateEmployeeRequest): Promise<Employee> {
    if (!USE_MOCK_API) {
        return staffFetch<Employee>("/api/employees", {
            method: "POST",
            body: JSON.stringify(request),
        });
    }

    assertUniqueCin(request.cin);
    assertUniqueEmail(request.email);

    const now = nowIsoDateTime();
    const createdEmployee: Employee = {
        id: getNextEmployeeId(),
        firstName: request.firstName,
        lastName: request.lastName,
        fullName: `${request.firstName} ${request.lastName}`.trim(),
        email: request.email ?? null,
        phone: request.phone ?? null,
        cin: request.cin,
        department: request.department,
        active: true,
        authUserId: null,
        createdAt: now,
        updatedAt: now,
    };

    employeeStore = [createdEmployee, ...employeeStore];

    return mockResponse(createdEmployee);
}

export async function updateEmployee(id: number, request: UpdateEmployeeRequest): Promise<Employee> {
    if (!USE_MOCK_API) {
        return staffFetch<Employee>(`/api/employees/${id}`, {
            method: "PUT",
            body: JSON.stringify(request),
        });
    }

    const currentEmployee = getEmployeeOrThrow(id);
    assertUniqueCin(request.cin, id);
    assertUniqueEmail(request.email, id);

    const updatedEmployee: Employee = {
        ...currentEmployee,
        ...request,
        email: request.email ?? null,
        phone: request.phone ?? null,
        fullName: `${request.firstName} ${request.lastName}`.trim(),
        updatedAt: nowIsoDateTime(),
    };

    employeeStore = employeeStore.map((employee) => employee.id === id ? updatedEmployee : employee);

    return mockResponse(updatedEmployee);
}

export async function deactivateEmployee(id: number): Promise<Employee> {
    if (!USE_MOCK_API) {
        return staffFetch<Employee>(`/api/employees/${id}/deactivate`, { method: "PATCH" });
    }

    const employee = getEmployeeOrThrow(id);
    const updatedEmployee = { ...employee, active: false, updatedAt: nowIsoDateTime() };
    employeeStore = employeeStore.map((item) => item.id === id ? updatedEmployee : item);

    return mockResponse(updatedEmployee);
}

export async function activateEmployee(id: number): Promise<Employee> {
    if (!USE_MOCK_API) {
        return staffFetch<Employee>(`/api/employees/${id}/activate`, { method: "PATCH" });
    }

    const employee = getEmployeeOrThrow(id);
    const updatedEmployee = { ...employee, active: true, updatedAt: nowIsoDateTime() };
    employeeStore = employeeStore.map((item) => item.id === id ? updatedEmployee : item);

    return mockResponse(updatedEmployee);
}

export async function linkAuthUser(id: number, request: LinkAuthUserRequest): Promise<Employee> {
    if (!USE_MOCK_API) {
        return staffFetch<Employee>(`/api/employees/${id}/link-user`, {
            method: "PATCH",
            body: JSON.stringify(request),
        });
    }

    const employee = getEmployeeOrThrow(id);
    if (employee.authUserId && employee.authUserId !== request.userId) {
        throw new Error("Cet employé est déjà lié à un autre compte utilisateur.");
    }

    assertAuthUserAvailable(request.userId, id);

    const updatedEmployee = { ...employee, authUserId: request.userId, updatedAt: nowIsoDateTime() };
    employeeStore = employeeStore.map((item) => item.id === id ? updatedEmployee : item);

    return mockResponse(updatedEmployee);
}

export async function unlinkAuthUser(id: number): Promise<Employee> {
    if (!USE_MOCK_API) {
        return staffFetch<Employee>(`/api/employees/${id}/unlink-user`, { method: "PATCH" });
    }

    const employee = getEmployeeOrThrow(id);
    const updatedEmployee = { ...employee, authUserId: null, updatedAt: nowIsoDateTime() };
    employeeStore = employeeStore.map((item) => item.id === id ? updatedEmployee : item);

    return mockResponse(updatedEmployee);
}

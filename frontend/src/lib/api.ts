const API_BASE_URL =
    process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

export class ApiError extends Error {
    constructor(
        public readonly status: number,
        message: string,
        public readonly fieldErrors: Record<string, string> = {}
    ) {
        super(message);
        this.name = "ApiError";
    }
}

export async function apiFetch<T>(
    path: string,
    options: RequestInit = {}
): Promise<T> {
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...(options.headers as Record<string, string> ?? {}),
    };

    if (typeof window !== "undefined") {
        const token = localStorage.getItem("accessToken");
        if (token) {
            headers["Authorization"] = `Bearer ${token}`;
        }
    }

    const response = await fetch(`${API_BASE_URL}${path}`, {
        ...options,
        headers,
    });

    if (!response.ok) {
        let message = `Erreur ${response.status}`;
        let fieldErrors: Record<string, string> = {};
        try {
            const body = await response.json() as {
                message?: string;
                fieldErrors?: Record<string, string>;
            };
            if (body.message) message = body.message;
            if (body.fieldErrors) fieldErrors = body.fieldErrors;
        } catch {
            // corps non-JSON, on garde le message générique
        }
        throw new ApiError(response.status, message, fieldErrors);
    }

    if (response.status === 204) {
        return undefined as T;
    }

    return response.json() as Promise<T>;
}

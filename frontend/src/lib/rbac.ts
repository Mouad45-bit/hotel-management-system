import type { UserRole } from "@/types/user";

export type SupportedRole = Exclude<UserRole, "HR">;

export type SidebarItemId =
    | "home"
    | "rooms"
    | "clients"
    | "reservations"
    | "invoices"
    | "housekeeping"
    | "my-housekeeping-tasks"
    | "staff"
    | "users";

export type PermissionKey =
    | "rooms:create"
    | "rooms:view"
    | "rooms:edit"
    | "rooms:deactivate"
    | "rooms:activate"
    | "rooms:change-status"
    | "rooms:reserve"
    | "rooms:reservation-history"
    | "clients:create"
    | "clients:view"
    | "clients:edit"
    | "clients:deactivate"
    | "clients:activate"
    | "clients:invoice-history"
    | "clients:reservation-history"
    | "reservations:create"
    | "reservations:view"
    | "reservations:edit"
    | "reservations:cancel"
    | "reservations:confirm"
    | "reservations:check-in"
    | "reservations:no-show"
    | "reservations:check-out"
    | "reservations:generate-invoice"
    | "reservations:view-invoice"
    | "invoices:create"
    | "invoices:view"
    | "invoices:print"
    | "invoices:issue"
    | "invoices:pay"
    | "invoices:cancel"
    | "invoices:refund"
    | "housekeeping:create-task"
    | "housekeeping:view-task"
    | "housekeeping:assign-agent"
    | "housekeeping:reassign-agent"
    | "housekeeping:cancel-task"
    | "housekeeping:start-task"
    | "housekeeping:complete-task"
    | "staff:create"
    | "staff:view"
    | "staff:edit"
    | "staff:activate"
    | "staff:deactivate"
    | "staff:delete"
    | "staff:link-account"
    | "staff:unlink-account"
    | "users:view-employee";

interface SidebarItemConfig {
    id: SidebarItemId;
    label: string;
    href: string;
    icon: string;
}

interface QuickAccessConfig {
    title: string;
    description: string;
    href: string;
    icon: string;
}

const SUPPORTED_ROLES: SupportedRole[] = [
    "ADMIN",
    "MANAGER",
    "RECEPTIONIST",
    "HOUSEKEEPING_AGENT",
];

export const ROLE_LABELS: Record<SupportedRole, string> = {
    ADMIN: "Administrateur",
    MANAGER: "Manager",
    RECEPTIONIST: "Réceptionniste",
    HOUSEKEEPING_AGENT: "Agent housekeeping",
};

const ROLE_HOME_PATHS: Record<SupportedRole, string> = {
    ADMIN: "/",
    MANAGER: "/",
    RECEPTIONIST: "/",
    HOUSEKEEPING_AGENT: "/",
};

export const SIDEBAR_ITEMS: Record<SidebarItemId, SidebarItemConfig> = {
    home: { id: "home", label: "Accueil", href: "/", icon: "LayoutGrid" },
    rooms: { id: "rooms", label: "Chambres", href: "/rooms", icon: "BedDouble" },
    clients: { id: "clients", label: "Clients", href: "/clients", icon: "Users" },
    reservations: { id: "reservations", label: "Réservations", href: "/reservations", icon: "CalendarDays" },
    invoices: { id: "invoices", label: "Factures", href: "/invoices", icon: "FileText" },
    housekeeping: { id: "housekeeping", label: "Housekeeping", href: "/housekeeping", icon: "Sparkles" },
    "my-housekeeping-tasks": { id: "my-housekeeping-tasks", label: "Mes tâches", href: "/housekeeping/my-tasks", icon: "ClipboardList" },
    staff: { id: "staff", label: "Personnel", href: "/staff", icon: "UserRoundCog" },
    users: { id: "users", label: "Comptes système", href: "/users", icon: "Shield" },
};

const SIDEBAR_BY_ROLE: Record<SupportedRole, SidebarItemId[]> = {
    ADMIN: ["home", "staff", "users"],
    MANAGER: ["home", "rooms", "housekeeping"],
    RECEPTIONIST: ["home", "rooms", "clients", "reservations", "invoices"],
    HOUSEKEEPING_AGENT: ["home", "my-housekeeping-tasks"],
};

const ROUTES_BY_ROLE: Record<SupportedRole, string[]> = {
    ADMIN: ["/", "/staff", "/staff/create", "/staff/:id", "/staff/:id/edit", "/users"],
    MANAGER: [
        "/",
        "/rooms",
        "/rooms/create",
        "/rooms/:id",
        "/rooms/:id/edit",
        "/housekeeping",
        "/housekeeping/tasks",
        "/housekeeping/tasks/create",
        "/housekeeping/tasks/:id",
        "/housekeeping/rooms/:roomId/history",
    ],
    RECEPTIONIST: [
        "/",
        "/rooms",
        "/rooms/:id",
        "/clients",
        "/clients/create",
        "/clients/:id",
        "/clients/:id/edit",
        "/clients/:id/invoices",
        "/reservations",
        "/reservations/create",
        "/reservations/:id",
        "/reservations/:id/edit",
        "/invoices",
        "/invoices/create",
        "/invoices/:id",
        "/invoices/:id/print",
    ],
    HOUSEKEEPING_AGENT: ["/", "/housekeeping/my-tasks", "/housekeeping/tasks/:id"],
};

const PERMISSIONS_BY_ROLE: Record<SupportedRole, PermissionKey[]> = {
    ADMIN: [
        "staff:create",
        "staff:view",
        "staff:edit",
        "staff:activate",
        "staff:deactivate",
        "staff:delete",
        "staff:link-account",
        "staff:unlink-account",
        "users:view-employee",
    ],
    MANAGER: [
        "rooms:create",
        "rooms:view",
        "rooms:edit",
        "rooms:deactivate",
        "rooms:activate",
        "rooms:change-status",
        "housekeeping:create-task",
        "housekeeping:view-task",
        "housekeeping:assign-agent",
        "housekeeping:reassign-agent",
        "housekeeping:cancel-task",
    ],
    RECEPTIONIST: [
        "rooms:view",
        "rooms:reserve",
        "clients:create",
        "clients:view",
        "clients:edit",
        "clients:deactivate",
        "clients:activate",
        "clients:invoice-history",
        "clients:reservation-history",
        "reservations:create",
        "reservations:view",
        "reservations:edit",
        "reservations:cancel",
        "reservations:confirm",
        "reservations:check-in",
        "reservations:no-show",
        "reservations:check-out",
        "reservations:generate-invoice",
        "reservations:view-invoice",
        "invoices:create",
        "invoices:view",
        "invoices:print",
        "invoices:issue",
        "invoices:pay",
        "invoices:cancel",
        "invoices:refund",
    ],
    HOUSEKEEPING_AGENT: [
        "housekeeping:view-task",
        "housekeeping:start-task",
        "housekeeping:complete-task",
    ],
};

export const QUICK_ACCESS_BY_ROLE: Record<SupportedRole, QuickAccessConfig[]> = {
    ADMIN: [
        { title: "Personnel", description: "Gérer les employés de l'hôtel.", href: "/staff", icon: "UserRoundCog" },
        { title: "Créer un employé", description: "Ajouter un nouveau membre du personnel.", href: "/staff/create", icon: "UserPlus" },
        { title: "Comptes système", description: "Consulter les comptes liés aux employés.", href: "/users", icon: "Shield" },
    ],
    MANAGER: [
        { title: "Chambres", description: "Suivre les chambres et leurs statuts.", href: "/rooms", icon: "BedDouble" },
        { title: "Créer une chambre", description: "Ajouter une chambre au référentiel.", href: "/rooms/create", icon: "Plus" },
        { title: "Housekeeping", description: "Piloter l'activité de nettoyage.", href: "/housekeeping", icon: "Sparkles" },
        { title: "Liste des tâches", description: "Suivre les tâches housekeeping.", href: "/housekeeping/tasks", icon: "ClipboardList" },
        { title: "Créer une tâche", description: "Planifier une tâche housekeeping.", href: "/housekeeping/tasks/create", icon: "ListPlus" },
    ],
    RECEPTIONIST: [
        { title: "Chambres", description: "Consulter les chambres disponibles.", href: "/rooms", icon: "BedDouble" },
        { title: "Clients", description: "Gérer les fiches clients.", href: "/clients", icon: "Users" },
        { title: "Créer un client", description: "Enregistrer un nouveau client.", href: "/clients/create", icon: "UserPlus" },
        { title: "Réservations", description: "Suivre les séjours planifiés.", href: "/reservations", icon: "CalendarDays" },
        { title: "Créer une réservation", description: "Réserver une chambre pour un client.", href: "/reservations/create", icon: "CalendarPlus" },
        { title: "Factures", description: "Consulter et traiter les factures.", href: "/invoices", icon: "FileText" },
    ],
    HOUSEKEEPING_AGENT: [
        { title: "Mes tâches", description: "Voir les tâches qui vous sont affectées.", href: "/housekeeping/my-tasks", icon: "ClipboardList" },
        { title: "Mes tâches à faire", description: "Filtrer les interventions à démarrer.", href: "/housekeeping/my-tasks?status=TODO", icon: "CircleDot" },
        { title: "Mes tâches en cours", description: "Retrouver les interventions démarrées.", href: "/housekeeping/my-tasks?status=IN_PROGRESS", icon: "Play" },
    ],
};

function isSupportedRole(role?: UserRole | null): role is SupportedRole {
    return Boolean(role && SUPPORTED_ROLES.includes(role as SupportedRole));
}

function pathMatchesPattern(pathname: string, pattern: string) {
    const normalizedPath = pathname.split("?")[0].replace(/\/+$/, "") || "/";
    const normalizedPattern = pattern.replace(/\/+$/, "") || "/";

    const pathParts = normalizedPath.split("/").filter(Boolean);
    const patternParts = normalizedPattern.split("/").filter(Boolean);

    if (pathParts.length !== patternParts.length) return false;

    return patternParts.every((part, index) => part.startsWith(":") || part === pathParts[index]);
}

export function getRoleHomePath(role?: UserRole | null) {
    return isSupportedRole(role) ? ROLE_HOME_PATHS[role] : "/";
}

export function canAccessRoute(role: UserRole | null | undefined, pathname: string) {
    if (pathname === "/login") return true;
    if (!isSupportedRole(role)) return false;

    return ROUTES_BY_ROLE[role].some((route) => pathMatchesPattern(pathname, route));
}

export function canPerformAction(role: UserRole | null | undefined, permission: PermissionKey) {
    if (!isSupportedRole(role)) return false;

    return PERMISSIONS_BY_ROLE[role].includes(permission);
}

export function getSidebarItemsForRole(role: UserRole | null | undefined) {
    if (!isSupportedRole(role)) return [];

    return SIDEBAR_BY_ROLE[role].map((id) => SIDEBAR_ITEMS[id]);
}

export function getQuickAccessForRole(role: UserRole | null | undefined) {
    if (!isSupportedRole(role)) return [];

    return QUICK_ACCESS_BY_ROLE[role].filter((item) => canAccessRoute(role, item.href));
}

export function getRoleLabel(role: UserRole | null | undefined) {
    return isSupportedRole(role) ? ROLE_LABELS[role] : "Rôle non autorisé";
}

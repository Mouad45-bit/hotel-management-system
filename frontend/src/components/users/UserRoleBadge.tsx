import { cn } from "@/lib/utils";
import type { UserRole } from "@/types/user";
import { getRoleLabel, type SupportedRole } from "@/lib/rbac";

const ROLE_BADGE_CLASSES: Record<SupportedRole, string> = {
    ADMIN: "bg-red-50 text-red-700 ring-red-200",
    MANAGER: "bg-indigo-50 text-indigo-700 ring-indigo-200",
    RECEPTIONIST: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    HOUSEKEEPING_AGENT: "bg-amber-50 text-amber-700 ring-amber-200",
};

interface UserRoleBadgeProps {
    role: UserRole;
    className?: string;
}

export function UserRoleBadge({ role, className }: UserRoleBadgeProps) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                ROLE_BADGE_CLASSES[role as SupportedRole] ?? "bg-zinc-50 text-zinc-700 ring-zinc-200",
                className
            )}
        >
            {getRoleLabel(role)}
        </span>
    );
}

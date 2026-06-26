import { Ban, CircleCheckBig } from "lucide-react";
import { cn } from "@/lib/utils";
import {
    DEPARTMENT_BADGE_CLASSES,
    DEPARTMENT_LABELS,
    type Department,
} from "@/types/staff";

export function DepartmentBadge({
    department,
    className,
}: {
    department: Department;
    className?: string;
}) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                DEPARTMENT_BADGE_CLASSES[department],
                className
            )}
        >
            {DEPARTMENT_LABELS[department]}
        </span>
    );
}

export function StaffStatusBadge({
    active,
    className,
}: {
    active: boolean;
    className?: string;
}) {
    const Icon = active ? CircleCheckBig : Ban;

    return (
        <span
            className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                active
                    ? "bg-emerald-50 text-emerald-700 ring-emerald-200"
                    : "bg-red-50 text-red-700 ring-red-200",
                className
            )}
        >
            <Icon aria-hidden="true" className="h-3.5 w-3.5" strokeWidth={1.8} />
            {active ? "Actif" : "Désactivé"}
        </span>
    );
}

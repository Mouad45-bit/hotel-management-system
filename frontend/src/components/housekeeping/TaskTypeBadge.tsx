import { cn } from "@/lib/utils";
import {
    HOUSEKEEPING_TYPE_BADGE_CLASSES,
    HOUSEKEEPING_TYPE_LABELS,
    type HousekeepingTaskType,
} from "@/types/housekeeping";

interface TaskTypeBadgeProps {
    type: HousekeepingTaskType;
    className?: string;
}

export function TaskTypeBadge({ type, className }: TaskTypeBadgeProps) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                HOUSEKEEPING_TYPE_BADGE_CLASSES[type],
                className
            )}
        >
            {HOUSEKEEPING_TYPE_LABELS[type]}
        </span>
    );
}

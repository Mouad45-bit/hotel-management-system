import { cn } from "@/lib/utils";
import {
    HOUSEKEEPING_STATUS_BADGE_CLASSES,
    HOUSEKEEPING_STATUS_LABELS,
    type HousekeepingTaskStatus,
} from "@/types/housekeeping";

interface HousekeepingStatusBadgeProps {
    status: HousekeepingTaskStatus;
    className?: string;
}

export function HousekeepingStatusBadge({
    status,
    className,
}: HousekeepingStatusBadgeProps) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                HOUSEKEEPING_STATUS_BADGE_CLASSES[status],
                className
            )}
        >
            {HOUSEKEEPING_STATUS_LABELS[status]}
        </span>
    );
}

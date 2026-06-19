import { cn } from "@/lib/utils";
import {
    PRIORITY_BADGE_CLASSES,
    PRIORITY_LABELS,
    type Priority,
} from "@/types/housekeeping";

interface PriorityBadgeProps {
    priority: Priority;
    className?: string;
}

export function PriorityBadge({ priority, className }: PriorityBadgeProps) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                PRIORITY_BADGE_CLASSES[priority],
                className
            )}
        >
            {PRIORITY_LABELS[priority]}
        </span>
    );
}

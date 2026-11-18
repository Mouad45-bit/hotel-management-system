import { cn } from "@/lib/utils";
import {
    formatHousekeepingDate,
    formatHousekeepingDateTime,
} from "@/lib/housekeepingHelpers";

interface HousekeepingDateProps {
    value?: string | null;
    withTime?: boolean;
    className?: string;
}

export function HousekeepingDate({
    value,
    withTime = false,
    className,
}: HousekeepingDateProps) {
    return (
        <time className={cn("text-sm text-zinc-700", className)}>
            {withTime
                ? formatHousekeepingDateTime(value)
                : formatHousekeepingDate(value)}
        </time>
    );
}

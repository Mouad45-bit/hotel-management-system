import { cn } from "@/lib/utils";

interface StaffDateProps {
    value?: string | null;
    withTime?: boolean;
    placeholder?: string;
    className?: string;
}

export function StaffDate({
    value,
    withTime = false,
    placeholder = "—",
    className,
}: StaffDateProps) {
    if (!value) {
        return <span className={className}>{placeholder}</span>;
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return <span className={className}>{value}</span>;
    }

    return (
        <time dateTime={value} className={className}>
            {date.toLocaleDateString("fr-FR", {
                day: "2-digit",
                month: "short",
                year: "numeric",
                ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
            })}
        </time>
    );
}

export function StaffInfoLine({
    label,
    value,
}: {
    label: string;
    value: string;
}) {
    return (
        <div className="flex items-center justify-between gap-4 border-b border-[var(--hms-soft-border)] py-3 last:border-b-0">
            <dt className="text-sm text-[var(--hms-text-muted)]">{label}</dt>
            <dd className={cn("text-right text-sm font-semibold text-[var(--hms-text)]", value === "—" && "text-[var(--hms-text-muted)]")}>{value}</dd>
        </div>
    );
}

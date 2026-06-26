import { cn } from "@/lib/utils";
import { formatInvoiceDate } from "@/lib/invoiceHelpers";

interface InvoiceDateProps {
    value?: string | null;
    className?: string;
    withTime?: boolean;
    placeholder?: string;
}

export function InvoiceDate({
    value,
    className,
    withTime = false,
    placeholder = "—",
}: InvoiceDateProps) {
    const formattedDate = value
        ? formatInvoiceDate(value, { withTime })
        : placeholder;

    return (
        <time
            dateTime={value ?? undefined}
            className={cn("text-sm text-[var(--hms-text-muted)]", className)}
        >
            {formattedDate}
        </time>
    );
}

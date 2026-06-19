import { cn } from "@/lib/utils";
import { formatInvoiceAmount } from "@/lib/invoiceHelpers";

interface InvoiceAmountProps {
    amount: number;
    className?: string;
    currency?: string;
    locale?: string;
    variant?: "default" | "strong" | "muted" | "success" | "danger";
}

export function InvoiceAmount({
    amount,
    className,
    currency = "MAD",
    locale = "fr-MA",
    variant = "default",
}: InvoiceAmountProps) {
    return (
        <span
            className={cn(
                "tabular-nums",
                variant === "default" && "font-medium text-zinc-900",
                variant === "strong" && "font-semibold text-zinc-950",
                variant === "muted" && "text-zinc-500",
                variant === "success" && "font-semibold text-emerald-700",
                variant === "danger" && "font-semibold text-red-700",
                amount < 0 && "text-red-700",
                className
            )}
        >
            {formatInvoiceAmount(amount, currency, locale)}
        </span>
    );
}

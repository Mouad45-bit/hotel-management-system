import {
    Ban,
    CircleCheckBig,
    Clock3,
    FileCheck2,
    RotateCcw,
    type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { getInvoiceStatusDisplayLabel } from "@/lib/invoiceHelpers";
import {
    INVOICE_STATUS_BADGE_CLASSES,
    type InvoiceStatus,
} from "@/types/invoice";

interface InvoiceStatusBadgeProps {
    status: InvoiceStatus;
    className?: string;
    showIcon?: boolean;
}

const STATUS_ICONS: Record<InvoiceStatus, LucideIcon> = {
    DRAFT: Clock3,
    ISSUED: FileCheck2,
    PAID: CircleCheckBig,
    CANCELLED: Ban,
    REFUNDED: RotateCcw,
};

export function InvoiceStatusBadge({
    status,
    className,
    showIcon = true,
}: InvoiceStatusBadgeProps) {
    const Icon = STATUS_ICONS[status];

    return (
        <span
            className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                INVOICE_STATUS_BADGE_CLASSES[status],
                className
            )}
        >
            {showIcon && <Icon aria-hidden="true" className="h-3.5 w-3.5" strokeWidth={1.8} />}

            {getInvoiceStatusDisplayLabel(status)}
        </span>
    );
}

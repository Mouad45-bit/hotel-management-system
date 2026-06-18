import type { ComponentType, SVGProps } from "react";
import {
    ArrowPathIcon,
    CheckCircleIcon,
    ClockIcon,
    DocumentCheckIcon,
    NoSymbolIcon,
} from "@heroicons/react/24/outline";
import { cn } from "@/lib/utils";
import { getInvoiceStatusDisplayLabel } from "@/lib/invoiceHelpers";
import {
    INVOICE_STATUS_BADGE_CLASSES,
    type InvoiceStatus,
} from "@/types/invoice";

type StatusIcon = ComponentType<SVGProps<SVGSVGElement>>;

interface InvoiceStatusBadgeProps {
    status: InvoiceStatus;
    className?: string;
    showIcon?: boolean;
}

const STATUS_ICONS: Record<InvoiceStatus, StatusIcon> = {
    DRAFT: ClockIcon,
    ISSUED: DocumentCheckIcon,
    PAID: CheckCircleIcon,
    CANCELLED: NoSymbolIcon,
    REFUNDED: ArrowPathIcon,
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
            {showIcon && <Icon aria-hidden="true" className="h-3.5 w-3.5" />}

            {getInvoiceStatusDisplayLabel(status)}
        </span>
    );
}

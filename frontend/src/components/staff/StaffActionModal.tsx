"use client";

import type { ReactNode } from "react";
import {
    Dialog,
    DialogBackdrop,
    DialogPanel,
    DialogTitle,
} from "@headlessui/react";
import { X, type LucideIcon } from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { cn } from "@/lib/utils";

interface StaffActionModalProps {
    open: boolean;
    title: string;
    description: string;
    icon: LucideIcon;
    iconClassName?: string;
    children: ReactNode;
    confirmLabel: string;
    submitting?: boolean;
    confirmDisabled?: boolean;
    danger?: boolean;
    onClose: () => void;
    onConfirm: () => void;
}

export function StaffActionModal({
    open,
    title,
    description,
    icon: Icon,
    iconClassName,
    children,
    confirmLabel,
    submitting = false,
    confirmDisabled = false,
    danger = false,
    onClose,
    onConfirm,
}: StaffActionModalProps) {
    return (
        <Dialog open={open} onClose={onClose} className="relative z-50">
            <DialogBackdrop className="fixed inset-0 bg-[rgba(13,9,7,0.42)]" />

            <div className="fixed inset-0 flex items-center justify-center p-4">
                <DialogPanel className="w-full max-w-xl rounded-[22px] bg-white shadow-[0_24px_70px_rgba(13,9,7,0.18)]">
                    <div className="flex items-start justify-between gap-4 border-b border-[var(--hms-soft-border)] px-6 py-5">
                        <div className="flex items-start gap-3">
                            <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl", iconClassName)}>
                                <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                            </div>

                            <div>
                                <DialogTitle className="text-base font-bold text-[var(--hms-text)]">
                                    {title}
                                </DialogTitle>
                                <p className="mt-1 text-sm leading-6 text-[var(--hms-text-muted)]">
                                    {description}
                                </p>
                            </div>
                        </div>

                        <button
                            type="button"
                            onClick={onClose}
                            disabled={submitting}
                            className="cursor-pointer rounded-xl p-2 text-[var(--hms-text-muted)] transition-colors hover:bg-slate-100 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] disabled:cursor-not-allowed disabled:opacity-60"
                            aria-label="Fermer"
                        >
                            <X aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        </button>
                    </div>

                    <div className="px-6 py-5">{children}</div>

                    <div className="flex flex-col-reverse gap-2 border-t border-[var(--hms-soft-border)] bg-slate-50 px-6 py-4 sm:flex-row sm:justify-end">
                        <HmsButton type="button" variant="secondary" onClick={onClose} disabled={submitting}>
                            Annuler
                        </HmsButton>
                        <HmsButton
                            type="button"
                            variant={danger ? "danger" : "primary"}
                            onClick={onConfirm}
                            disabled={submitting || confirmDisabled}
                        >
                            {submitting ? "Traitement..." : confirmLabel}
                        </HmsButton>
                    </div>
                </DialogPanel>
            </div>
        </Dialog>
    );
}

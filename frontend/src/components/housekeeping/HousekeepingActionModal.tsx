"use client";

import type { ComponentType, ReactNode, SVGProps } from "react";
import {
    Dialog,
    DialogBackdrop,
    DialogPanel,
    DialogTitle,
} from "@headlessui/react";
import { XMarkIcon } from "@heroicons/react/24/outline";
import { HmsButton } from "@/components/hms/HmsButton";
import { cn } from "@/lib/utils";

type ModalIcon = ComponentType<SVGProps<SVGSVGElement>>;

interface HousekeepingActionModalProps {
    open: boolean;
    title: string;
    description: string;
    children: ReactNode;
    icon: ModalIcon;
    iconClassName?: string;
    confirmLabel: string;
    cancelLabel?: string;
    submitting?: boolean;
    confirmDisabled?: boolean;
    danger?: boolean;
    onClose: () => void;
    onConfirm: () => void;
}

export function HousekeepingActionModal({
    open,
    title,
    description,
    children,
    icon: Icon,
    iconClassName,
    confirmLabel,
    cancelLabel = "Annuler",
    submitting = false,
    confirmDisabled = false,
    danger = false,
    onClose,
    onConfirm,
}: HousekeepingActionModalProps) {
    return (
        <Dialog open={open} onClose={onClose} className="relative z-50">
            <DialogBackdrop className="fixed inset-0 bg-zinc-950/40" />
            <div className="fixed inset-0 flex items-center justify-center p-4">
                <DialogPanel className="w-full max-w-xl rounded-2xl bg-white shadow-xl">
                    <div className="flex items-start justify-between gap-4 border-b border-zinc-200 px-6 py-5">
                        <div className="flex items-start gap-3">
                            <div
                                className={cn(
                                    "flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl",
                                    iconClassName
                                )}
                            >
                                <Icon className="h-5 w-5" />
                            </div>
                            <div>
                                <DialogTitle className="text-base font-semibold text-zinc-950">
                                    {title}
                                </DialogTitle>
                                <p className="mt-1 text-sm leading-6 text-zinc-500">
                                    {description}
                                </p>
                            </div>
                        </div>
                        <button
                            type="button"
                            onClick={onClose}
                            disabled={submitting}
                            className="rounded-xl p-2 text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-700 disabled:cursor-not-allowed disabled:opacity-60"
                            aria-label="Fermer"
                        >
                            <XMarkIcon className="h-5 w-5" />
                        </button>
                    </div>
                    <div className="px-6 py-5">{children}</div>
                    <div className="flex flex-col-reverse gap-2 border-t border-zinc-200 bg-zinc-50 px-6 py-4 sm:flex-row sm:justify-end">
                        <HmsButton
                            type="button"
                            variant="secondary"
                            onClick={onClose}
                            disabled={submitting}
                        >
                            {cancelLabel}
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

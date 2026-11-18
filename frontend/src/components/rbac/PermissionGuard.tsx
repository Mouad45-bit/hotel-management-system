"use client";

import type { ReactNode } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { canPerformAction, type PermissionKey } from "@/lib/rbac";

interface PermissionGuardProps {
    permission: PermissionKey;
    children: ReactNode;
}

export function PermissionGuard({ permission, children }: PermissionGuardProps) {
    const { user } = useAuth();

    if (!canPerformAction(user?.role, permission)) return null;

    return children;
}

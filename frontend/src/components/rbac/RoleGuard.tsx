"use client";

import type { ReactNode } from "react";
import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";
import { canAccessRoute, getRoleHomePath } from "@/lib/rbac";

interface RoleGuardProps {
    children: ReactNode;
}

export function RoleGuard({ children }: RoleGuardProps) {
    const { user, isLoading } = useAuth();
    const pathname = usePathname();
    const router = useRouter();
    const allowed = Boolean(user && canAccessRoute(user.role, pathname));

    useEffect(() => {
        if (isLoading || !user || allowed) return;

        router.replace(`${getRoleHomePath(user.role)}?unauthorized=1`);
    }, [allowed, isLoading, router, user]);

    if (isLoading || !user) {
        return (
            <div className="flex min-h-[40vh] items-center justify-center text-sm font-medium text-[var(--hms-text-muted)]">
                Chargement de votre session...
            </div>
        );
    }

    if (!allowed) {
        return (
            <div className="flex min-h-[40vh] items-center justify-center text-sm font-medium text-[var(--hms-text-muted)]">
                Redirection vers votre accueil...
            </div>
        );
    }

    return children;
}

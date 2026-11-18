import { z } from "zod";
import {
    DEPARTMENTS,
    type StaffSearchParams,
} from "@/types/staff";

function emptyStringToUndefined(value: unknown) {
    if (typeof value === "string" && value.trim() === "") {
        return undefined;
    }

    return value;
}

const optionalText = (max: number, message: string) =>
    z.preprocess(
        emptyStringToUndefined,
        z.string().trim().max(max, message).optional()
    );

export const departmentSchema = z.enum(DEPARTMENTS);

export const staffFormSchema = z.object({
    firstName: z
        .string()
        .trim()
        .min(1, "Le prénom est obligatoire.")
        .max(80, "Le prénom ne doit pas dépasser 80 caractères."),
    lastName: z
        .string()
        .trim()
        .min(1, "Le nom est obligatoire.")
        .max(80, "Le nom ne doit pas dépasser 80 caractères."),
    cin: z
        .string()
        .trim()
        .min(1, "Le CIN est obligatoire.")
        .max(40, "Le CIN ne doit pas dépasser 40 caractères."),
    email: z.preprocess(
        emptyStringToUndefined,
        z
            .email("L’adresse email est invalide.")
            .max(160, "L’email ne doit pas dépasser 160 caractères.")
            .optional()
    ),
    phone: optionalText(40, "Le téléphone ne doit pas dépasser 40 caractères."),
    department: departmentSchema,
});

export const linkAuthUserSchema = z.object({
    userId: z.coerce
        .number()
        .int("L’identifiant utilisateur doit être un nombre entier.")
        .positive("L’identifiant utilisateur doit être positif."),
});

export const staffFiltersSchema = z.object({
    keyword: z
        .string()
        .trim()
        .max(120, "La recherche ne doit pas dépasser 120 caractères."),
    department: z.union([z.literal("ALL"), departmentSchema]),
    active: z.union([z.literal("ALL"), z.literal("ACTIVE"), z.literal("INACTIVE")]),
});

export type StaffFormValues = z.infer<typeof staffFormSchema>;
export type LinkAuthUserFormValues = z.infer<typeof linkAuthUserSchema>;
export type StaffFiltersFormValues = z.infer<typeof staffFiltersSchema>;

export function toStaffSearchParams(
    filters: StaffFiltersFormValues
): StaffSearchParams {
    return {
        keyword: filters.keyword || undefined,
        department: filters.department === "ALL" ? undefined : filters.department,
        active:
            filters.active === "ALL"
                ? undefined
                : filters.active === "ACTIVE",
    };
}

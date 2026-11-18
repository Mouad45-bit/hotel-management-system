import { z } from "zod";
import {
    HOUSEKEEPING_TASK_STATUSES,
    HOUSEKEEPING_TASK_TYPES,
    PRIORITIES,
    type HousekeepingTaskSearchParams,
} from "@/types/housekeeping";

const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;

function emptyStringToUndefined(value: unknown) {
    if (typeof value === "string" && value.trim() === "") {
        return undefined;
    }

    return value;
}

const optionalTextSchema = z.preprocess(
    emptyStringToUndefined,
    z.string().trim().max(500, "Le texte ne doit pas dépasser 500 caractères.").optional()
);

const requiredIsoDateSchema = z
    .string()
    .regex(ISO_DATE_REGEX, "La date doit respecter le format YYYY-MM-DD.");

const optionalIsoDateStringSchema = z
    .string()
    .trim()
    .refine(
        (value) => value === "" || ISO_DATE_REGEX.test(value),
        "La date doit respecter le format YYYY-MM-DD."
    );

const positiveIdSchema = z.coerce
    .number()
    .int("L’identifiant doit être un nombre entier.")
    .positive("L’identifiant doit être positif.");

const optionalPositiveIdSchema = z.preprocess(
    emptyStringToUndefined,
    positiveIdSchema.optional()
);

const optionalPositiveIntegerStringSchema = z
    .string()
    .trim()
    .refine(
        (value) => value === "" || /^\d+$/.test(value),
        "La valeur doit être un nombre entier positif."
    );

export const housekeepingTaskStatusSchema = z.enum(HOUSEKEEPING_TASK_STATUSES);

export const housekeepingTaskTypeSchema = z.enum(HOUSEKEEPING_TASK_TYPES);

export const prioritySchema = z.enum(PRIORITIES);

export const housekeepingStatusFilterSchema = z.union([
    z.literal("ALL"),
    housekeepingTaskStatusSchema,
]);

export const housekeepingTypeFilterSchema = z.union([
    z.literal("ALL"),
    housekeepingTaskTypeSchema,
]);

export const priorityFilterSchema = z.union([z.literal("ALL"), prioritySchema]);

export const createHousekeepingTaskSchema = z.object({
    roomId: positiveIdSchema,
    reservationId: optionalPositiveIdSchema,
    assignedAgentId: optionalPositiveIdSchema,
    type: housekeepingTaskTypeSchema,
    priority: prioritySchema,
    scheduledDate: requiredIsoDateSchema,
    notes: optionalTextSchema,
});

export const updateHousekeepingTaskSchema = z.object({
    type: housekeepingTaskTypeSchema.optional(),
    priority: prioritySchema.optional(),
    scheduledDate: requiredIsoDateSchema.optional(),
    notes: optionalTextSchema,
});

export const assignHousekeepingTaskSchema = z.object({
    assignedAgentId: positiveIdSchema,
});

export const cancelHousekeepingTaskSchema = z.object({
    reason: z
        .string()
        .trim()
        .min(1, "Le motif d’annulation est obligatoire.")
        .max(500, "Le motif ne doit pas dépasser 500 caractères."),
});

export const housekeepingFiltersSchema = z.object({
    status: housekeepingStatusFilterSchema,
    type: housekeepingTypeFilterSchema,
    priority: priorityFilterSchema,
    roomId: optionalPositiveIntegerStringSchema,
    agentId: optionalPositiveIntegerStringSchema,
    scheduledDate: optionalIsoDateStringSchema,
});

export type CreateHousekeepingTaskFormValues = z.infer<
    typeof createHousekeepingTaskSchema
>;

export type UpdateHousekeepingTaskFormValues = z.infer<
    typeof updateHousekeepingTaskSchema
>;

export type AssignHousekeepingTaskFormValues = z.infer<
    typeof assignHousekeepingTaskSchema
>;

export type CancelHousekeepingTaskFormValues = z.infer<
    typeof cancelHousekeepingTaskSchema
>;

export type HousekeepingFiltersFormValues = z.infer<
    typeof housekeepingFiltersSchema
>;

export function toHousekeepingSearchParams(
    filters: HousekeepingFiltersFormValues
): HousekeepingTaskSearchParams {
    return {
        status: filters.status === "ALL" ? undefined : filters.status,
        type: filters.type === "ALL" ? undefined : filters.type,
        priority: filters.priority === "ALL" ? undefined : filters.priority,
        roomId: filters.roomId ? Number(filters.roomId) : undefined,
        agentId: filters.agentId ? Number(filters.agentId) : undefined,
        scheduledDate: filters.scheduledDate || undefined,
    };
}

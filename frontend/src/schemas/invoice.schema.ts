import { z } from "zod";
import {
    INVOICE_STATUSES,
    PAYMENT_METHODS,
    type InvoiceSearchParams,
} from "@/types/invoice";

const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;

const ISO_LOCAL_DATE_TIME_REGEX =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;

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

const requiredReasonSchema = z
    .string()
    .trim()
    .min(1, "Le motif est obligatoire.")
    .max(500, "Le motif ne doit pas dépasser 500 caractères.");

const optionalIsoDateSchema = z.preprocess(
    emptyStringToUndefined,
    z
        .string()
        .regex(ISO_DATE_REGEX, "La date doit respecter le format YYYY-MM-DD.")
        .optional()
);

const optionalIsoLocalDateTimeSchema = z.preprocess(
    emptyStringToUndefined,
    z
        .string()
        .regex(
            ISO_LOCAL_DATE_TIME_REGEX,
            "La date et l’heure doivent respecter le format YYYY-MM-DDTHH:mm."
        )
        .optional()
);

const optionalPositiveIntegerStringSchema = z
    .string()
    .trim()
    .refine(
        (value) => value === "" || /^\d+$/.test(value),
        "La valeur doit être un nombre entier positif."
    );

export const invoiceStatusSchema = z.enum(INVOICE_STATUSES);

export const invoiceStatusFilterSchema = z.union([
    z.literal("ALL"),
    invoiceStatusSchema,
]);

export const paymentMethodSchema = z.enum(PAYMENT_METHODS);

export const invoiceIdSchema = z.coerce
    .number()
    .int("L’identifiant de facture doit être un nombre entier.")
    .positive("L’identifiant de facture doit être positif.");

export const reservationIdSchema = z.coerce
    .number()
    .int("L’identifiant de réservation doit être un nombre entier.")
    .positive("L’identifiant de réservation doit être positif.");

export const generateInvoiceSchema = z.object({
    reservationId: reservationIdSchema,

    taxRate: z.coerce
        .number()
        .min(0, "Le taux de taxe doit être supérieur ou égal à 0."),

    notes: optionalTextSchema,
});

export const generateInvoiceRequestSchema = generateInvoiceSchema.omit({
    reservationId: true,
});

export const issueInvoiceSchema = z.object({
    issueDate: optionalIsoDateSchema,
});

export const payInvoiceSchema = z.object({
    paymentMethod: paymentMethodSchema,

    paymentReference: z.preprocess(
        emptyStringToUndefined,
        z
            .string()
            .trim()
            .max(
                120,
                "La référence de paiement ne doit pas dépasser 120 caractères."
            )
            .optional()
    ),

    paidAt: optionalIsoLocalDateTimeSchema,
});

export const cancelInvoiceSchema = z.object({
    reason: requiredReasonSchema,
});

export const refundInvoiceSchema = z.object({
    reason: requiredReasonSchema,

    paymentReference: z.preprocess(
        emptyStringToUndefined,
        z
            .string()
            .trim()
            .max(
                120,
                "La référence de remboursement ne doit pas dépasser 120 caractères."
            )
            .optional()
    ),

    refundedAt: optionalIsoLocalDateTimeSchema,
});

export const invoiceFiltersSchema = z
    .object({
        number: z
            .string()
            .trim()
            .max(
                50,
                "Le numéro de facture ne doit pas dépasser 50 caractères."
            ),

        status: invoiceStatusFilterSchema,

        clientId: optionalPositiveIntegerStringSchema,

        reservationId: optionalPositiveIntegerStringSchema,

        from: z
            .string()
            .trim()
            .refine(
                (value) => value === "" || ISO_DATE_REGEX.test(value),
                "La date de début doit respecter le format YYYY-MM-DD."
            ),

        to: z
            .string()
            .trim()
            .refine(
                (value) => value === "" || ISO_DATE_REGEX.test(value),
                "La date de fin doit respecter le format YYYY-MM-DD."
            ),
    })
    .superRefine((filters, context) => {
        if (filters.from && filters.to && filters.from > filters.to) {
            context.addIssue({
                code: "custom",
                path: ["to"],
                message:
                    "La date de fin doit être supérieure ou égale à la date de début.",
            });
        }
    });

export type GenerateInvoiceFormValues = z.infer<typeof generateInvoiceSchema>;

export type GenerateInvoiceRequestValues = z.infer<
    typeof generateInvoiceRequestSchema
>;

export type IssueInvoiceFormValues = z.infer<typeof issueInvoiceSchema>;

export type PayInvoiceFormValues = z.infer<typeof payInvoiceSchema>;

export type CancelInvoiceFormValues = z.infer<typeof cancelInvoiceSchema>;

export type RefundInvoiceFormValues = z.infer<typeof refundInvoiceSchema>;

export type InvoiceFiltersFormValues = z.infer<typeof invoiceFiltersSchema>;

export function toInvoiceSearchParams(
    filters: InvoiceFiltersFormValues
): InvoiceSearchParams {
    return {
        number: filters.number || undefined,

        status: filters.status === "ALL" ? undefined : filters.status,

        clientId: filters.clientId ? Number(filters.clientId) : undefined,

        reservationId: filters.reservationId
            ? Number(filters.reservationId)
            : undefined,

        from: filters.from || undefined,

        to: filters.to || undefined,
    };
}

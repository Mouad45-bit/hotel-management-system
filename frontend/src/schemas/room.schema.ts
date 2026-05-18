import { z } from "zod";

export const roomTypeSchema = z.enum([
    "SINGLE",
    "DOUBLE",
    "TWIN",
    "SUITE",
    "FAMILY",
    "DELUXE",
]);

export const roomStatusSchema = z.enum([
    "AVAILABLE",
    "RESERVED",
    "OCCUPIED",
    "CLEANING",
    "MAINTENANCE",
    "OUT_OF_SERVICE",
]);

export const roomSchema = z.object({
    number: z.string().min(1, "Le numéro est obligatoire"),
    floor: z.coerce
        .number()
        .min(0, "L’étage doit être supérieur ou égal à 0"),
    type: roomTypeSchema,
    pricePerNight: z.coerce.number().min(0, "Le prix doit être positif"),
    capacity: z.coerce
        .number()
        .min(1, "La capacité doit être supérieure à 0"),
    status: roomStatusSchema,
    description: z.string().optional(),
});

export type RoomFormValues = z.infer<typeof roomSchema>;

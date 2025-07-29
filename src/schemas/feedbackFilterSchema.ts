import { z } from "zod";

export const feedbackFilterSchema = z.object({
    feedbackCategory: z
    .string()
    .min(1),
    feedbackType: z
    .string()
    .min(7)
    .max(11)
})
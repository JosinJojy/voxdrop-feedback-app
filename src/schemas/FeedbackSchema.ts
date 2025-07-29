import { z } from "zod";

export const feedbackSchema = z.object({
  content: z
    .string()
    .min(1, { message: " Empty messages can't be send " })
    .max(10000, { message: "Content must be no longer than 10000 charectors" }),

  cacategory:z
  .string()

})

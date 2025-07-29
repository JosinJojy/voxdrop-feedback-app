import { Feedback } from "@/models/UserModel";

export type FeedbackCardProps = {
  feedback: Feedback | undefined;
  filters: { categoryId: string; type: string };
};

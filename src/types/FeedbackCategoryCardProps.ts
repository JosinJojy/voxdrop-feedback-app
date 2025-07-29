import { FeedbackCategory } from "@/models/UserModel";

export type feedbackCategoryDetails = {
  _id?: string | unknown;
  title: string;
  createdAt: Date;
  isAcceptingThisCategory: boolean;
  userId: string;
};

export type FeedbackCategoryProps = {
  feedbackCategoryDetails: FeedbackCategory;
  userId: string;
};

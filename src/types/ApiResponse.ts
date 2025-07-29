import { Feedback, FeedbackCategory  } from "@/models/UserModel";

export interface ApiResponse{
    success: boolean;
    message: string;
    feedbacks?: Array<Feedback>
    feedbackCategoryDetails?: Array<FeedbackCategory>
    nextPage?: number
}
import { FeedbackResponseType } from "./FeedbacksResponseType";

export type InitialFeedbacksType = {
    success:boolean;
    feedbacks:FeedbackResponseType;
    nextPage: number | undefined
}
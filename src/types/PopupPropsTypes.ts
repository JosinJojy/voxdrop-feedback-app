import { Feedback } from "@/models/UserModel";

export type ViewFeedbackProps = {
  selectedFeedback: Feedback | null;
  closeFeedbackPopup: (close: null) => void;
  handleDelete: (targer: Feedback | null) => void;
};

export type DeleteConfirmation = {
  deleteTarget: Feedback | null;
  onDeleteFeedback: (deleteTargetId: string, categoryId: string) => void;
};

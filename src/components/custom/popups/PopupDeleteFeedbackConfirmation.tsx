import {
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { DeleteConfirmation } from "@/types/PopupPropsTypes";
import { AlertTriangle, Trash2 } from "lucide-react";

const PopupDeleteFeedbackConfirmation = ({
  deleteTarget,
  onDeleteFeedback,
}: DeleteConfirmation) => {
  return (
    <AlertDialogContent className="max-w-md">
      <AlertDialogHeader>
        <div className="flex items-center space-x-3 mb-2">
          <div className="w-12 h-12 rounded-full bg-red-100 dark:bg-red-900 flex items-center justify-center">
            <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
          </div>
          <div>
            <AlertDialogTitle className="text-lg">
              Delete Feedback Message
            </AlertDialogTitle>
          </div>
        </div>
        <AlertDialogDescription className="text-base leading-relaxed">
          <>
            Are you sure you want to delete this feedback for &quot;
            {deleteTarget?.feedbackCategoryTitle}&quot; ?
            <br />
            <br />
            <span className="text-red-600 dark:text-red-400 font-medium">
              This action cannot be undone.
            </span>
          </>
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter className="gap-2">
        <AlertDialogCancel>Cancel</AlertDialogCancel>
        <AlertDialogAction
          onClick={() => {
            onDeleteFeedback(
              deleteTarget?._id?.toString() || "",
              deleteTarget?.feedbackCategoryId.toString() || ""
            );
          }}
          className="bg-red-600 hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-800"
        >
          <Trash2 className="h-4 w-4 mr-2" />
          Delete Message
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  );
};

export default PopupDeleteFeedbackConfirmation;

import {
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Calendar, Quote, Trash2 } from "lucide-react";
import {
  formatDate,
  getCategoryColor,
  getCategoryGradient,
  getCategoryIcon,
} from "@/helpers/feedback-card-helpers";
import { AlertDialog, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { ViewFeedbackProps } from "@/types/PopupPropsTypes";

const PopupFeedbackView = ({
  selectedFeedback,
  closeFeedbackPopup,
  handleDelete,
}: ViewFeedbackProps) => {
  return (
    <DialogContent className="max-w-2xl max-h-[80vh] overflow-hidden">
      {selectedFeedback && (
        <div className="space-y-6">
          {/* Header with gradient background */}
          <div
            className={`relative p-6 -m-6 mb-0 bg-gradient-to-br ${getCategoryGradient(selectedFeedback.feedbackType)} rounded-t-lg border-b `}
          >
            <div className="absolute inset-0 bg-grid-white/10 bg-grid-16 [mask-image:linear-gradient(0deg,white,rgba(255,255,255,0.6))]" />
            <div className="relative">
              <DialogHeader className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-12 h-12 rounded-full bg-white/20 backdrop-blur-sm flex items-center justify-center text-2xl">
                      {getCategoryIcon(selectedFeedback.feedbackType)}
                    </div>
                    <div>
                      <DialogTitle className="text-xl font-bold text-foreground">
                        Anonymous Feedback
                      </DialogTitle>
                      <DialogDescription className="text-muted-foreground">
                        {selectedFeedback.feedbackCategoryTitle}
                      </DialogDescription>
                    </div>
                  </div>
                  <Badge
                    variant="secondary"
                    className={`${getCategoryColor(selectedFeedback.feedbackType)} font-medium text-sm px-3 py-1`}
                  >
                    {selectedFeedback.feedbackType}
                  </Badge>
                </div>
              </DialogHeader>
            </div>
          </div>

          {/* Feedback Content */}
          <div className="space-y-6">
            {/* Quote Section */}
            <div className="relative mt-6">
              <Quote className="absolute -top-2 -left-2 h-8 w-8 text-primary/20" />
              <div className="bg-muted/50 rounded-lg p-6 ml-4 max-h-40 sm:max-h-52 md:max-h-60 overflow-y-auto w-full overflow-x-hidden">
                <p className="text-base leading-relaxed font-medium break-all whitespace-pre-wrap overflow-hidden overflow-ellipsis">
                  {selectedFeedback.content}
                </p>
              </div>
            </div>

            {/* Metadata */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-center space-x-3 p-4 bg-muted/30 rounded-lg">
                <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                  <Calendar className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium">Submitted</p>
                  <p className="text-sm text-muted-foreground">
                    {formatDate(selectedFeedback.createdAt.toString())}
                  </p>
                </div>
              </div>
            </div>
            {/* Action Buttons */}
            <div className="flex justify-end space-x-3 pt-4 border-t">
              <Button
                variant="outline"
                onClick={() => closeFeedbackPopup(null)}
              >
                Close
              </Button>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button
                    variant="outline"
                    className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950 border-red-200 dark:border-red-800"
                    onClick={() => handleDelete(selectedFeedback)} // delete here
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete
                  </Button>
                </AlertDialogTrigger>
              </AlertDialog>
            </div>
          </div>
        </div>
      )}
    </DialogContent>
  );
};

export default PopupFeedbackView;

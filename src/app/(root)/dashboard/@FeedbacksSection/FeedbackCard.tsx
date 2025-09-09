"use client";
import { AlertDialog, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Clock, Eye, MessageSquare, Trash2 } from "lucide-react";
import { useState } from "react";
import { Dialog } from "@/components/ui/dialog";
import { toast } from "sonner";
import { Feedback } from "@/models/UserModel";
import {
  formatDate,
  getCategoryColor,
  getCategoryIcon,
} from "@/helpers/feedback-card-helpers";
import { FeedbackCardProps } from "@/types/FeedbackCardProps";
import { useDeleteFeedback } from "@/hooks/useFeedbackActions";
import PopupFeedbackView from "@/components/custom/popups/PopupFeedbackView";
import PopupDeleteFeedbackConfirmation from "@/components/custom/popups/PopupDeleteFeedbackConfirmation";
import AnimatedCard from "@/components/custom/animations/AnimatedCard";

const FeedbackCard = ({ feedback, filters }: FeedbackCardProps) => {

  const [selectedFeedback, setSelectedFeedback] = useState<Feedback | null>(
    null
  );
  const [deleteTarget, setDeleteTarget] = useState<Feedback | null>(null);
  const deleteMutation = useDeleteFeedback(filters);

  const onDeleteFeedback = async (deleteTargetId: string, categoryId: string) => {
    deleteMutation.mutate(
      { id: deleteTargetId, 
        categoryId
       },
      {
        onSuccess: () => {
          toast.success("Feedback deleted successfully", {
            position: "top-center",
          });
        },
      }
    );
  };

  const closeFeedbackPopup = () => {
    setSelectedFeedback(null);
  };

  const handleDelete = (deleteTarget: Feedback | null) => {
    setDeleteTarget(deleteTarget);
  };

  return (
    <AnimatedCard>
      <Card className="group hover:shadow-lg transition-all duration-300 cursor-pointer border-l-4 order-l-white/50 dark:border-l-white/20 hover:border-l-primary dark:hover:border-l-primary">
        <CardHeader>
          <div className="flex justify-between items-start">
            <div className="flex items-center space-x-2">
              <MessageSquare className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">
                {feedback?.feedbackCategoryTitle}
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <Badge
                variant="outline"
                className={`${getCategoryColor(feedback?.feedbackType || "general")} font-medium`}
              >
                <span className="mr-1">
                  {getCategoryIcon(feedback?.feedbackType || "general")}
                </span>
                {feedback?.feedbackType}
              </Badge>
              <div className="flex items-center text-xs text-muted-foreground">
                <Clock className="h-3 w-3 mr-1" />
                {formatDate(feedback?.createdAt?.toString() || '')}
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex justify-between items-start">
            <p className="text-sm leading-relaxed line-clamp-2 flex-1 mr-4">
              {feedback?.content}
            </p>
            <div className="flex items-center space-x-1 transition-opacity duration-200 shrink-0">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedFeedback(feedback ? feedback : null)} // Message in detail
              >
                <Eye className="h-4 w-4 mr-2" />
                View
              </Button>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-neutral-800 dark:text-white hover:text-red-700 dark:hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950"
                    onClick={() => setDeleteTarget(feedback ? feedback : null)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </AlertDialogTrigger>
              </AlertDialog>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Feedback details popup */}
      <Dialog
        open={!!selectedFeedback}
        onOpenChange={() => setSelectedFeedback(null)}
      >
        <PopupFeedbackView
          selectedFeedback={selectedFeedback}
          closeFeedbackPopup={closeFeedbackPopup}
          handleDelete={handleDelete}
        />
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={() => setDeleteTarget(null)}
      >
        <PopupDeleteFeedbackConfirmation
          deleteTarget={deleteTarget}
          onDeleteFeedback={onDeleteFeedback}
        />
      </AlertDialog>
    </AnimatedCard>
  );
};

export default FeedbackCard;

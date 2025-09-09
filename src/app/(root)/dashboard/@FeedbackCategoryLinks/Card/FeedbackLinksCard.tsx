"use client";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AlertDialog, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ExternalLink, Share2, Trash2 } from "lucide-react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import {
  feedbackCategoryDetails,
  FeedbackCategoryProps,
} from "@/types/FeedbackCategoryCardProps";
import { AlertTriangle } from "lucide-react";
import {
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import CopyToClipboard from "./CopyToClipboard";
import AcceptFeedbackSwitch from "./AcceptFeedbackSwitch";
import axios, { AxiosError } from "axios";
import { toast } from "sonner";
import { ApiResponse } from "@/types/ApiResponse";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { formatDate } from "@/helpers/feedback-card-helpers";
import AnimatedCard from "@/components/custom/animations/AnimatedCard";

const FeedbackLinksCard = ({
  feedbackCategoryDetails,
  userId,
}: FeedbackCategoryProps) => {
  const [deleteTarget, setDeleteTarget] =
    useState<feedbackCategoryDetails | null>(null);

  const router = useRouter();

  const handleDeleteFeedbackCategory = async () => {
    try {
      const response = await axios.delete<ApiResponse>(
        "/api/delete-feedback-category",
        {
          params: {
            categoryId: feedbackCategoryDetails._id,
          },
        }
      );
      toast.success(response.data.message, { position: "top-center" });
      router.refresh();
    } catch (error) {
      const axiosError = error as AxiosError<ApiResponse>;
      toast.error("Action failed", {
        description:
          axiosError.response?.data?.message ?? "Error deleting feedback",
        position: "top-center",
      });
    }
  };

  return (
    <AnimatedCard >
      <Card className="group hover:shadow-lg hover:border-primary  transition-all duration-300">
        <CardHeader>
          <div className="flex flex-col sm:flex-row gap-2 justify-between items-start">
            <div>
              <CardTitle className="text-lg transition-colors">
                {feedbackCategoryDetails.title}
              </CardTitle>
              <CardDescription>
                Created{" "}
                {formatDate(feedbackCategoryDetails.createdAt.toString())}
              </CardDescription>
            </div>
            <div className="flex justify-between sm:justify-end items-center space-x-2 w-full sm:w-auto">
              <AcceptFeedbackSwitch
                initialState={feedbackCategoryDetails.isAcceptingThisCategory}
                feedbackCategoryId={feedbackCategoryDetails?._id || ""}
              />
              <div className="flex items-center">
                <Badge
                  variant="secondary"
                  className="group-hover:bg-primary/10 transition-colors"
                >
                  {feedbackCategoryDetails?.count }{" "}
                  {feedbackCategoryDetails?.count && feedbackCategoryDetails?.count > 1 ? 'responses' : 'response'}
                </Badge>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="transition duration-200 text-neutral-700 dark:text-white hover:text-red-700 dark:hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950"
                      onClick={() => setDeleteTarget(feedbackCategoryDetails)} //Delete here
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </AlertDialogTrigger>
                </AlertDialog>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2 mb-4">
            <Input
              value={`${process.env.NEXT_PUBLIC_BASE_URL}/feedback?userId=${userId}&categoryId=${feedbackCategoryDetails._id}`}
              readOnly
              className="flex-1 text-sm"
            />
            <CopyToClipboard
              userId={userId}
              feedbackCategoryId={feedbackCategoryDetails._id!}
            />
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="flex-1 hover:bg-primary hover:text-primary-foreground transition-colors"
            >
              <Share2 className="h-4 w-4 mr-2" />
              Share
            </Button>
            <Link
              href={`/feedback?userId=${userId}&categoryId=${feedbackCategoryDetails._id}`}
              rel="noopener noreferrer"
              target="_blank"
            >
              <Button
                size="sm"
                variant="outline"
                className="hover:bg-primary hover:text-primary-foreground transition-colors"
              >
                <ExternalLink className="h-4 w-4 mr-2" />
                View
              </Button>
            </Link>
          </div>
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={() => setDeleteTarget(null)}
      >
        <AlertDialogContent className="max-w-md">
          <AlertDialogHeader>
            <div className="flex items-center space-x-3 mb-2">
              <div className="w-12 h-12 rounded-full bg-red-100 dark:bg-red-900 flex items-center justify-center">
                <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
              </div>
              <div>
                <AlertDialogTitle className="text-lg">
                  Delete Feedback Category
                </AlertDialogTitle>
              </div>
            </div>
            <AlertDialogDescription className="text-base leading-relaxed">
              <>
                Are you sure you want to delete this category for &quot;
                {deleteTarget?.title}&quot; ?
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
                handleDeleteFeedbackCategory();
              }}
              className="bg-red-600 hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-800"
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Delete category
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </AnimatedCard>
  );
};

export default FeedbackLinksCard;

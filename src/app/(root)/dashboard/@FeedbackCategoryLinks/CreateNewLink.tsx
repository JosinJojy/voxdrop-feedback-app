"use client";

import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Loader2, Plus } from "lucide-react";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import axios, { AxiosError } from "axios";
import { ApiResponse } from "@/types/ApiResponse";
import { toast } from "sonner";
import { useRouter } from 'next/navigation';

const placeholders = [
  "Share your feedback...",
  "Ask me anything",
  "Project Feedback",
  "Drop a thought!",
  "Team Meeting Feedback",
  "Anything to Say ??"
];

const CreateNewLink = ({userId}:{userId:string}) => {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [feedbackCategoryTitle, setFeedbackCategoryTitle] = useState("");
  const [index, setIndex] = useState(0);

  const router = useRouter()

  useEffect(() => {
    const interval = setInterval(() => {
      setIndex((prev) => (prev + 1) % placeholders.length);
    }, 2100); // change every 2 seconds

    return () => clearInterval(interval);
  }, []);

  const handleAddLink = async () => {
    //Create new link here
    setIsLoading(true);
    try {
      const response = await axios.post<ApiResponse>(
        "/api/add-feedback-category",
        { feedbackCategoryTitle, userId }
      );
      toast.success("Success", {
        description:
          response?.data?.message ?? "new feedback category added successfuly",
        position: "top-center",
      });

      router.refresh()

    } catch (error) {
      const axiosError = error as AxiosError<ApiResponse>;
      toast.error("Error", {
        description:
          axiosError.response?.data?.message ?? "Error adding new category",
        position: "top-center",
      });
    } finally {
      setIsLoading(false);
      setIsCreateDialogOpen(false);
    }
  };

  //TODO use react-hook-form

  return (
    <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
      <DialogTrigger asChild>
        <Button className="sm:mt-0">
          <Plus className="h-4 w-4" />
          <p className="hidden sm:block">Create New Link</p>
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Feedback Link</DialogTitle>
          <DialogDescription>
            Create a new anonymous feedback link to share with others
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="title">Link Title</Label>
            <Input
              id="title"
              placeholder={placeholders[index]}
              value={feedbackCategoryTitle}
              onChange={(e) => setFeedbackCategoryTitle(e.target.value)}
              className="mt-4"
            />
          </div>
          <div className="flex justify-end space-x-2">
            <Button
              variant="outline"
              onClick={() => setIsCreateDialogOpen(false)}
              disabled={isLoading}
              className="cursor-pointer"
            >
              Cancel
            </Button>
            <Button
              onClick={() => handleAddLink()}
              disabled={isLoading}
              className="cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading
                </>
              ) : (
                "Create Link"
              )}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default CreateNewLink;

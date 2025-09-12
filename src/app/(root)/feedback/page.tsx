"use client";

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import * as RadioGroup from "@radix-ui/react-radio-group";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import {
  Send,
  Shield,
  MessageCircle,
  Heart,
  Lightbulb,
  AlertTriangle,
  MessageSquare,
  Lock,
  Loader,
  Sparkles,
} from "lucide-react";
import { feedbackSchema } from "@/schemas/FeedbackSchema";
import { FeedbackCategory } from "@/models/UserModel";
import axios, { AxiosError } from "axios";
import { ApiResponse } from "@/types/ApiResponse";
import SubmitSuccessMessage from "@/components/custom/SubmitSuccessMessage";
import { FeedbackType } from "@/helpers/feedback-card-helpers";
import AnimateText from "@/components/custom/animations/AnimateText";
import DivFadeIn from "@/components/custom/animations/DivFadeIn";
import Link from "next/link";

export default function FeedbackSubmission() {
  const [userId, setUserId] = useState("");
  const [feedbackCategoryId, setFeedbackCategoryId] = useState("");
  const [feedbackDetails, setFeedbackDetails] = useState<FeedbackCategory>();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [aiFeedbacks, setAiFeedbacks] = useState<string[]>([]);

  const getFeedbackCategoryDetails = async (
    userId: string,
    feedbackCategoryId: string
  ) => {
    try {
      const response = await axios.get<ApiResponse>(
        "/api/get-feedback-category-details",
        {
          params: {
            userId,
            feedbackCategoryId,
          },
        }
      );
      if (response.data?.feedbackCategoryDetails !== undefined) {
        setFeedbackDetails(response.data?.feedbackCategoryDetails[0]);
      }
    } catch (error) {
      const axiosError = error as AxiosError<ApiResponse>;
      toast.error("Error", {
        description:
          axiosError.response?.data?.message ??
          "failed to get feedback category details",
        position: "top-center",
      });
    }
  };

  const { register, handleSubmit, setValue, watch } = useForm<
    z.infer<typeof feedbackSchema>
  >({
    resolver: zodResolver(feedbackSchema),
  });

  useEffect(() => {
    const userIdFromURL = window.location.search.split("&")[0].split("=")[1];
    const feedbackCategoryIdFromURL = window.location.search
      .split("&")[1]
      .split("=")[1];
    setUserId(userIdFromURL);
    setFeedbackCategoryId(feedbackCategoryIdFromURL);
    getFeedbackCategoryDetails(userIdFromURL, feedbackCategoryIdFromURL);
    setValue("cacategory", "general");
  }, []);

  type FeedbackForm = z.infer<typeof feedbackSchema>;

  const category = watch("cacategory");

  const onSubmit = async (data: z.infer<typeof feedbackSchema>) => {
    setIsSubmitting(true);

    try {
      const content = data.content;
      const feedbackCategoryTitle = feedbackDetails?.title;
      const feedbackType = data.cacategory;
      const response = await axios.post<ApiResponse>("/api/send-feedback", {
        userId,
        content,
        feedbackCategoryId,
        feedbackCategoryTitle,
        feedbackType,
      });
      setIsSubmitted(true);
      toast.success(response.data.message, { position: "top-center" });
    } catch (error) {
      const axiosError = error as AxiosError<ApiResponse>;
      toast.error("Error", {
        description:
          axiosError.response?.data?.message ?? "failed to send feedback",
        position: "top-center",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const getAIgeneratedFeedback = async () => {
    setAiFeedbacks([]);
    setLoading(true);

    const res = await fetch("/api/suggest-ai-generated-feedback");

    const reader = res.body?.getReader();
    const decoder = new TextDecoder();

    let buffer = "";
    while (reader) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value);
      buffer += chunk;
      const parts = buffer.split("¤");

      for (let i = 0; i < parts.length - 1; i++) {
        setAiFeedbacks((prev) => [...prev, parts[i]]);
      }

      buffer = parts[parts.length - 1];
    }
    if (buffer.trim()) {
      console.log("buffer =", buffer, "\ntrim =", buffer.trim());
      setAiFeedbacks((prev) => [...prev, buffer.trim()]);
    }
    setLoading(false);
  };

  const getCategoryIcon = (cat: string) => {
    switch (cat) {
      case "positive":
        return <Heart className="h-5 w-5 text-green-600" />;
      case "improvement":
        return <Lightbulb className="h-5 w-5 text-yellow-600" />;
      case "concern":
        return <AlertTriangle className="h-5 w-5 text-red-600" />;
      default:
        return <MessageSquare className="h-5 w-5 text-blue-600" />;
    }
  };

  const handleAddNewFeedback = () => {
    setIsSubmitted(false);
    setValue("cacategory", "general");
    setValue("content", "");
  };

  if (isSubmitted) {
    return <SubmitSuccessMessage addNewFeedback={handleAddNewFeedback} />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary/5 via-background to-secondary/5">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-2">
        <div className="max-w-3xl mx-auto mt-16">
          {/* Header Section */}
          <div className="text-center mb-8 sm:mb-10 md:mb-12">
            <div className="relative mb-8">
              <div className="absolute inset-0 bg-primary/20 rounded-full blur-xl w-20 h-20 mx-auto animate-pulse" />
            </div>

            <DivFadeIn>
              <Badge
                variant="outline"
                className="mb-4 px-4 py-2 text-sm font-medium"
              >
                <Shield className="h-4 w-4 mr-2 text-green-500" />
                100% Anonymous Feedback
              </Badge>
            </DivFadeIn>

            <AnimateText
              className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-4 bg-gradient-to-r from-primary to-primary/80 bg-clip-text dark:text-white text-primary"
              isHeading={true}
            >
              {feedbackDetails?.title ? (
                feedbackDetails?.title
              ) : (
                <div className="flex items-center justify-center w-full">
                  <Loader className="animate-spin transition duration-200" />
                </div>
              )}
            </AnimateText>
            <AnimateText className="text-xs sm:text-sm text-muted-foreground leading-relaxed max-w-2xl mx-auto">
              `Share your honest thoughts about &quot;{feedbackDetails?.title}
              &quot;. Your feedback is completely anonymous and helps us improve
              our collaboration and productivity`
            </AnimateText>
          </div>

          {/* Main Feedback Form */}
          <DivFadeIn viewport={0.1}>
            <Card className="shadow-2xl border-2 transition-all duration-300">
              <CardContent className="p-6">
                <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                  {/* Feedback Text Area */}
                  <div className="space-y-2">
                    <Label
                      htmlFor="feedback"
                      className="text-lg font-semibold flex items-center space-x-2"
                    >
                      <MessageCircle className="h-5 w-5 text-primary" />
                      <span>Your Feedback</span>
                      <span className="text-red-500">*</span>
                    </Label>

                    <div className="relative">
                      <Textarea
                        {...register("content")}
                        placeholder="Share your feedback"
                        className="min-h-[150px] resize-y text-base leading-relaxed border-2 focus:border-primary transition-colors"
                        required
                      />
                    </div>
                  </div>

                  {/* Category Selection */}
                  <div className="space-y-4">
                    <Label className="text-lg font-semibold flex items-center space-x-2">
                      <MessageSquare className="h-5 w-5 text-primary" />
                      <span>What type of feedback is this?</span>
                      <span className="text-sm font-normal text-muted-foreground">
                        (Optional)
                      </span>
                    </Label>

                    <RadioGroup.Root
                      defaultValue="general"
                      className="w-full grid grid-cols-1 sm:grid-cols-2 gap-6"
                      value={category}
                      onValueChange={(newValue) =>
                        setValue(
                          "cacategory",
                          newValue as FeedbackForm["cacategory"]
                        )
                      }
                    >
                      {FeedbackType.map((option) => (
                        <RadioGroup.Item
                          key={option.value}
                          value={option.value}
                          className="ring-[1px] ring-border rounded-md py-1 px-3 data-[state=checked]:ring-2 data-[state=checked]:ring-primary transition duration-150"
                        >
                          <div className="flex flex-col md:flex-row items-center justify-center gap-2 py-2">
                            <div>{getCategoryIcon(option.value)}</div>
                            <div>
                              <div className="font-semibold text-base">
                                {option.label}
                              </div>
                              <div className="text-sm text-muted-foreground">
                                {option.desc}
                              </div>
                            </div>
                          </div>
                        </RadioGroup.Item>
                      ))}
                    </RadioGroup.Root>
                  </div>

                  {/* Submit Button */}
                  <div className="flex flex-col space-y-4">
                    <Button
                      type="submit"
                      className="w-full py-6 md:text-lg font-semibold bg-gradient-to-r from-primary to-primary/90 hover:from-primary/90 hover:to-primary shadow-lg hover:shadow-xl transition-all duration-300"
                      disabled={isSubmitting}
                    >
                      {isSubmitting ? (
                        <>
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3" />
                          Submitting Your Feedback...
                        </>
                      ) : (
                        <>
                          <Send className="h-5 w-5 mr-3" />
                          Submit Anonymous Feedback
                        </>
                      )}
                    </Button>

                    <p className="text-center text-sm text-muted-foreground">
                      By submitting, you confirm that your feedback is honest
                      and constructive
                    </p>
                  </div>
                </form>
                <div className="flex flex-col gap-2 items-center justify-center mt-1">
                  <div className="flex flex-col gap-4 mb-0.5">
                    {aiFeedbacks?.map((feedback, index) => {
                      console.log(feedback, "\n\n");
                      return (
                        <div
                          key={index}
                          className="p-4 border rounded-md hover:border-primary active:border-primary transition duration-150 cursor-pointer"
                          onClick={() => setValue("content", feedback)}
                        >
                          <h1>{feedback}</h1>
                        </div>
                      );
                    })}
                  </div>
                  <div>
                    <Button
                      onClick={() => getAIgeneratedFeedback()}
                      disabled={loading}
                    >
                      {loading && (
                        <Loader className="animate-spin transition duration-200" />
                      )}
                      <Sparkles />
                      Generate AI feedback
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </DivFadeIn>

          {/* Footer */}
          <div className="text-center mt-12 space-y-4">
            <div className="flex items-center justify-center space-x-6 text-sm text-muted-foreground">
              <div className="flex items-center space-x-2">
                <Shield className="h-4 w-4 text-green-500" />
                <span>Secure</span>
              </div>
              <div className="flex items-center space-x-2">
                <Lock className="h-4 w-4 text-blue-500" />
                <span>Anonymous</span>
              </div>
              <div className="flex items-center space-x-2">
                <Heart className="h-4 w-4 text-red-500" />
                <span>Trusted</span>
              </div>
            </div>

            <p className="text-sm text-muted-foreground">
              Powered by{" "}
              <Link href="/">
                <span className="font-semibold text-primary">Voxdrop</span> •
              </Link>
              <span className="ml-2">Making feedback safe and anonymous</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

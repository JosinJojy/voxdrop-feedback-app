"use client";
import { useEffect, useState } from "react";
import { Loader2, RefreshCcw } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import FeedbackCard from "./FeedbackCard";
import { Button } from "@/components/ui/button";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { feedbackFilterSchema } from "@/schemas/feedbackFilterSchema";
import * as z from "zod";
import { useFeedbacks } from "../../../../hooks/useFeedbackActions";
import InfiniteScrollContainer from "./InfiniteScrollContainer";
import SkeletonFeedbackSection from "@/components/custom/skeleton/SkeletonFeedbackSection";
import ErrorFetchFeedbacks from "@/components/custom/ErrorFetchFeedbacks";
import { InfiniteScrollProps } from "@/types/InfiniteScrollProps";

const InfiniteScrollFeedbacks = ({ allFeedbackCategories }: InfiniteScrollProps) => {
  const form = useForm<z.infer<typeof feedbackFilterSchema>>({
    resolver: zodResolver(feedbackFilterSchema),
    defaultValues: {
      feedbackCategory: "All Categories",
      feedbackType: "All Types",
    },
  });

  const { control, setValue } = form;

  const category = useWatch({ control, name: "feedbackCategory" });
  const type = useWatch({ control, name: "feedbackType" });

  const [isFiltersReady, setFiltersReady] = useState(false);

  useEffect(() => {
    if (category && type) {
      setFiltersReady(true);
    }
  }, [category, type]);

  const {
    data,
    isPending,
    isFetching,
    isError,
    error,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    refetch,
  } = useFeedbacks({ categoryId: category, type }, isFiltersReady);

  const feedbacks = data?.pages.flatMap((page) => page.feedbacks);

  if (isPending) {
    return <SkeletonFeedbackSection />;
  }

  if (isError) {
    return <ErrorFetchFeedbacks error={error} />;
  }

  return (
    <div className="space-y-6 flex flex-col h-full">
      <div className="flex  md:flex-row gap-y-4 items-center justify-between">
        <h2 className="text-xl font-semibold">Recent Feedback</h2>
        <div className="flex gap-3 items-center">
          <Button
            className="my-1 cursor-pointer"
            variant="outline"
            onClick={(e) => {
              e.preventDefault();
              refetch();
            }}
          >
            {isFetching ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCcw className="h-4 w-4" />
            )}
          </Button>
          <div className="flex flex-col sm:flex-row lg:flex-col xl:flex-row gap-2">
            {allFeedbackCategories.length > 1 && (
              <Select
                onValueChange={(val) =>
                  setValue("feedbackCategory", val, { shouldValidate: true })
                }
                defaultValue={category}
              >
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="All Category" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectLabel>Categories</SelectLabel>
                    <SelectItem value="All Categories">
                      All Categories
                    </SelectItem>
                    {allFeedbackCategories.map((category) => (
                      <SelectItem
                        value={category?._id || ""}
                        key={category?._id || ""}
                      >
                        {category?.title}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            )}
            <Select
              onValueChange={(val) =>
                setValue("feedbackType", val, { shouldValidate: true })
              }
              defaultValue={type}
            >
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectLabel>Feedback Type</SelectLabel>
                  <SelectItem value="All Types">All types</SelectItem>
                  <SelectItem value="general">general</SelectItem>
                  <SelectItem value="positive">positive</SelectItem>
                  <SelectItem value="improvement">improvement</SelectItem>
                  <SelectItem value="concern">concern</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      {/* Scrollable Container */}
      <div className="flex-1 overflow-hidden">
        <div className="max-h-[600px] overflow-y-auto  pr-2 space-y-4 scrollbar-thin scrollbar-thumb-muted-foreground/20 scrollbar-track-transparent hover:scrollbar-thumb-muted-foreground/40">
          <InfiniteScrollContainer
            onBottomReached={() =>
              hasNextPage && !isFetchingNextPage && fetchNextPage()
            }
            isFetchingNextPage={isFetchingNextPage}
            className="flex flex-col gap-4"
          >
            {feedbacks?.map((feedback, index) => (
              <FeedbackCard
                key={index}
                feedback={feedback}
                filters={{ categoryId: category, type }}
              />
            ))}
          </InfiniteScrollContainer>
        </div>
      </div>
    </div>
  );
};

export default InfiniteScrollFeedbacks;

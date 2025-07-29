import { getAllFeedbackCategories } from "@/actions/getAllFeedbackCategories";
import InfiniteScrollFeedbacks from "@/app/(root)/dashboard/@FeedbacksSection/InfiniteScrollFeedbacks";

export default async function FeedbacksWrapper() {
  const categoryResponse = await getAllFeedbackCategories();
  const AllFeedbackCategories = categoryResponse?.AllCategories as [
    { _id: string | undefined; title: string } | null,
  ];

  return (
    <InfiniteScrollFeedbacks allFeedbackCategories={AllFeedbackCategories} />
  );
}

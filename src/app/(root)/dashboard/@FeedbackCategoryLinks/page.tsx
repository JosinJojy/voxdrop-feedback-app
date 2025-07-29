import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import Link from "next/link";
import { getAllFeedbackCategoryDetails } from "@/actions/getAllFeedbackCategoryDetails";
import FeedbackLinksCard from "@/app/(root)/dashboard/@FeedbackCategoryLinks/Card/FeedbackLinksCard";
import CreateNewLink from "@/app/(root)/dashboard/@FeedbackCategoryLinks/CreateNewLink";
import { Badge } from "@/components/ui/badge";
import { FeedbackCategory } from "@/models/UserModel";

const FeedbackCategoryContainer = async () => {
  const session = await getServerSession(authOptions);

  if (!session?.user || !session?.user?._id) {
    return <Link href={"/signin"}>Sign in</Link>;
  }

  const allFeedbackCategoriesDetails = await getAllFeedbackCategoryDetails(
    session?.user?._id
  ) as [FeedbackCategory]

  console.log("Category loaded");
  return (
    <div className="space-y-6 flex flex-col h-full">
      <div className="flex items-center justify-between px-2">
        <h2 className="text-xl font-semibold">Your Feedback Links</h2>
        <div className="flex items-center">
          <Badge variant="secondary" className="text-xs px-4 py-2 mr-2">
            0 links
          </Badge>
          <CreateNewLink userId={session?.user?._id} />
        </div>
      </div>
      <div className="flex-1 overflow-hidden">
        <div className="max-h-[600px] overflow-y-auto pr-2 space-y-4 scrollbar-thin scrollbar-thumb-muted-foreground/20 scrollbar-track-transparent hover:scrollbar-thumb-muted-foreground/40">
          {allFeedbackCategoriesDetails.map((CategoryDetails, index) => (
            <FeedbackLinksCard
              key={index}
              feedbackCategoryDetails={CategoryDetails}
              userId={session?.user?._id?.toString() || ""}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

export default FeedbackCategoryContainer;

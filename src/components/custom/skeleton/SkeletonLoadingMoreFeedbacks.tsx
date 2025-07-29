import { Skeleton } from "@/components/ui/skeleton";
import { Loader2 } from "lucide-react";
import React from "react";

const SkeletonLoadingMoreFeedbacks = () => {
  return (
    <div className="flex flex-col items-center justify-center gap-y-4 w-full">
      <Skeleton className="h-[125px] w-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
      <Skeleton className="h-[125px] w-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
      <Skeleton className="h-[125px] w-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
      <Skeleton className="h-[125px] w-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
      <Loader2 className="h-16 w-16 animate-spin text-primary" />
    </div>
  );
};

export default SkeletonLoadingMoreFeedbacks;

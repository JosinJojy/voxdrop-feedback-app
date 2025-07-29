"use client";
import SkeletonLoadingMoreFeedbacks from "@/components/custom/skeleton/SkeletonLoadingMoreFeedbacks";
import { useInView } from "react-intersection-observer";

interface InfiniteScrollContainerProps {
  children: React.ReactNode;
  onBottomReached: () => void;
  isFetchingNextPage: boolean;
  className?: string;
}

export default function InfiniteScrollContainer({
  children,
  onBottomReached,
  isFetchingNextPage,
  className,
}: InfiniteScrollContainerProps) {
  const { ref } = useInView({
    rootMargin: "10px",
    onChange(inView) {
      if (inView) {
        onBottomReached();
      }
    },
  });

  return (
    <div className={className ? className : ""}>
      {children}
      <div ref={ref} />
      <div className="flex items-center justify-center">
        {isFetchingNextPage && (
          <SkeletonLoadingMoreFeedbacks/>
        )}
      </div>
    </div>
  );
}

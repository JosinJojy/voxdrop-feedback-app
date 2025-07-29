import { Skeleton } from "@/components/ui/skeleton"

const Loading = () => {
  return (
    <div className="flex flex-col gap-4 w-full h-[600px]">
      <Skeleton className="w-full h-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
      <Skeleton className="w-full h-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
      <Skeleton className="w-full h-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
    </div>
  );
};

export default Loading;

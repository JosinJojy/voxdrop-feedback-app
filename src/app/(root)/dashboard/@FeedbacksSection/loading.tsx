import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loader2 } from "lucide-react";

const Loading = () => {
  return (
    <div>
      <div className="flex flex-col md:flex-row gap-y-4 items-center justify-between">
        <h2 className="text-xl font-semibold">Recent Feedback</h2>
        <div className="flex gap-3 items-center">
          <Button className="my-1 cursor-pointer" variant="outline">
            <Loader2 className="h-4 w-4 animate-spin" />
          </Button>
          <div className="flex flex-col md:flex-row gap-2">
            <Select>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Category" />
              </SelectTrigger>
            </Select>
            <Select>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
            </Select>
          </div>
          <Badge variant="secondary" className="text-xs px-4 py-2">
            <Loader2 className="h-4 w-4 animate-spin" />
          </Badge>
        </div>
      </div>
      <div className="flex flex-col gap-4 w-full h-[600px] mt-4">
        <Skeleton className="w-full h-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
        <Skeleton className="w-full h-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
        <Skeleton className="w-full h-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
        <Skeleton className="w-full h-full rounded-lg dark:bg-neutral-800 bg-neutral-300" />
      </div>
    </div>
  );
};

export default Loading;

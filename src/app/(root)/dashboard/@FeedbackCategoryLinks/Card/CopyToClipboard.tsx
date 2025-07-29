"use client";
import { Button } from "@/components/ui/button";
import { Copy } from "lucide-react";
import { toast } from "sonner";

const CopyToClipboard = ({
  userId,
  feedbackCategoryId,
}: {
  userId: string;
  feedbackCategoryId: string | unknown;
}) => {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Link copied to clipboard!");
  };

  return (
    <Button
      size="sm"
      variant="outline"
      onClick={() =>
        copyToClipboard(
          `${process.env.NEXT_PUBLIC_BASE_URL}/feedback?userId=${userId}&categoryId=${feedbackCategoryId}`
        )
      }
      className="hover:bg-primary hover:text-primary-foreground transition-colors"
    >
      <Copy className="h-4 w-4" />
    </Button>
  );
};

export default CopyToClipboard;

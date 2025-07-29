"use client";

import { useForm } from "react-hook-form";
import * as z from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { acceptFeedbackSchema } from "@/schemas/acceptFeedbackSchema";
import { useState } from "react";
import axios from "axios";
import { ApiResponse } from "@/types/ApiResponse";
import { toast } from "sonner";
import { Switch } from "@/components/ui/switch";
import { AccepFeedbackSwitchProps } from "@/types/AcceptFeedbackSwitchProps";

const AcceptFeedbackSwitch = ({ initialState, feedbackCategoryId}: AccepFeedbackSwitchProps) => {
  
  const { setValue, watch } = useForm<z.infer<typeof acceptFeedbackSchema>>({
    resolver: zodResolver(acceptFeedbackSchema),
    defaultValues: {
      isEnabled: initialState,
    },
  });

  const isEnabled = watch("isEnabled");
  const [isSaving, setIsSaving] = useState(false);

  const handleSwitchChange = async (newValue: boolean) => {
    setValue("isEnabled", newValue, { shouldValidate: true });
    setIsSaving(true);

    try {
      const response = await axios.post<ApiResponse>(
        "/api/accept-feedbacks-specific-category",
        {
          acceptFeedbacks: newValue,
          feedbackCategoryId,
        }
      );
      toast.success("Success", {
        description: response.data.message,
        position: "top-center",
      });
    } catch (error) {
      console.log("Error updating the message staus ", error);
      toast("Error updating the message staus");
      setValue("isEnabled", !isEnabled);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="flex items-center gap-2">
      accept feedback
      <Switch
        checked={isEnabled}
        onCheckedChange={handleSwitchChange}
        disabled={isSaving}
        className="cursor-pointer"
      />
    </div>
  );
};

export default AcceptFeedbackSwitch;

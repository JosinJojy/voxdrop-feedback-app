"use client";
import { useForm } from "react-hook-form";
import { useState } from "react";
import * as z from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { verifySchema } from "@/schemas/verifySchema";
import { useParams, useRouter } from "next/navigation";
import axios, { AxiosError } from "axios";
import { ApiResponse } from "@/types/ApiResponse";
import { toast } from "sonner";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "@/components/ui/form";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSeparator,
  InputOTPSlot,
} from "@/components/ui/input-otp";

import { Button } from "@/components/ui/button";

const VerifyCode = () => {
  const router = useRouter();
  const param = useParams<{ username: string }>();

  const [isSubmitting, setIsSubmitting] = useState(false);

  const form = useForm<z.infer<typeof verifySchema>>({
    resolver: zodResolver(verifySchema),
  });

  const onSubmit = async (data: z.infer<typeof verifySchema>) => {
    try {
      setIsSubmitting(true);
      const response = await axios.post<ApiResponse>("/api/verify-code", {
        username: param.username,
        code: data.code,
      });
      toast.success(response.data.message);
      setIsSubmitting(false);
      router.replace("/signin");
    } catch (error) {
      const axiosError = error as AxiosError<ApiResponse>;
      toast.error("Verification failed", {
        description:
          axiosError.response?.data?.message ?? "Error checking username",
        position:'top-center'
      });
      setIsSubmitting(false);
    }
  };

  return (
    <div className="p-4 md:p-0 flex justify-center items-center min-h-screen dark:bg-neutral-950 bg-gray-100">
      <div className="w-full max-w-md p-8 space-y-8 rounded-lg dark:bg-neutral-900 bg-white border shadow-md">
        <div className="text-center">
          <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl mb-6">
            Verify you Account
          </h1>
          <p className="mb-4 text-neutral-300">
            Enter the verification code send to your email
          </p>
        </div>
        <div className="flex items-center justify-center">
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
              <FormField
                control={form.control}
                name="code"
                render={({ field }) => (
                  <FormItem>
                    <FormControl>
                      <InputOTP maxLength={6} {...field}>
                        <InputOTPGroup>
                          <InputOTPSlot index={0} />
                          <InputOTPSlot index={1} />
                          <InputOTPSlot index={2} />
                        </InputOTPGroup>
                        <InputOTPSeparator />
                        <InputOTPGroup>
                          <InputOTPSlot index={3} />
                          <InputOTPSlot index={4} />
                          <InputOTPSlot index={5} />
                        </InputOTPGroup>
                      </InputOTP>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button
                type="submit"
                disabled={isSubmitting}
                className="w-full cursor-pointer"
              >
                {isSubmitting ? "Loading...." : "Verify Code"}
              </Button>
            </form>
          </Form>
        </div>
      </div>
    </div>
  );
};

export default VerifyCode;

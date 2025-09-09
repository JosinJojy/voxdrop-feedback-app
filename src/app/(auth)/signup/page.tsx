"use client";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { useEffect, useState } from "react";
import { useDebounceCallback } from "usehooks-ts";
import { zodResolver } from "@hookform/resolvers/zod";
import { signUpSchema } from "@/schemas/signUpSchema";
import axios, { AxiosError } from "axios";
import { ApiResponse } from "@/types/ApiResponse";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import AnimateText from "@/components/custom/animations/AnimateText";
import DivFadeIn from "@/components/custom/animations/DivFadeIn";

const SignUp = () => {
  const [username, setUsername] = useState("");
  const [usernameMessage, setUsernameMessage] = useState("");
  const [isCheckingUsername, setIsCheckingUsername] = useState(false);
  const [isUsernameUnique, setIsUsernameUnique] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const debouncedUsername = useDebounceCallback(setUsername, 350);
  const router = useRouter();

  const form = useForm<z.infer<typeof signUpSchema>>({
    resolver: zodResolver(signUpSchema),
    defaultValues: {
      username: "",
      email: "",
      password: "",
    },
  });

  useEffect(() => {
    const checkUsernameTaken = async () => {
      if (username) {
        setIsCheckingUsername(true);
        try {
          const response = await axios.get<ApiResponse>(
            `/api/check-username-unique?username=${username}`
          );
          const message = response.data.message;
          setUsernameMessage(message);
          setIsUsernameUnique(true);
        } catch (error) {
          const axiosError = error as AxiosError<ApiResponse>;
          setUsernameMessage(
            axiosError.response?.data?.message ?? "Error checking username"
          );
          setIsUsernameUnique(false);
        } finally {
          setIsCheckingUsername(false);
        }
      } else {
        setUsernameMessage("");
      }
    };

    checkUsernameTaken();
  }, [username]);

  const onSubmit = async (data: z.infer<typeof signUpSchema>) => {
    console.log(data);
    setIsSubmitting(true);
    try {
      const response = await axios.post<ApiResponse>("/api/signup", data);
      const message = response.data.message;
      toast.success(message);
      router.replace(`/verify-code/${username}`);
    } catch (error) {
      const axiosError = error as AxiosError<ApiResponse>;
      toast.error("SignUp failed", {
        description:
          axiosError.response?.data?.message ?? "Error checking username",
        position: "top-center",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="p-4 md:p-0 flex justify-center items-center min-h-screen bg-radial-[at_50%_75%] from-primary/10 via-background to-primary/5 to-95%">
      <div className="w-full max-w-md p-8 space-y-8 rounded-lg dark:bg-neutral-900 bg-white border shadow-md">
        <div className="text-center">
          <AnimateText
            className="text-4xl font-extrabold tracking-tight lg:text-5xl mb-6"
            isHeading={true}
          >
            Try VOXDROP Feedback
          </AnimateText>
          <AnimateText className="mb-4 text-neutral-300">
            Sign up to start your anonymous adventure
          </AnimateText>
        </div>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <DivFadeIn initial={5}>
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Username</FormLabel>
                    <FormControl>
                      <Input
                        type="text"
                        placeholder="talk-to-me"
                        {...field}
                        onChange={(e) => {
                          field.onChange(e);
                          debouncedUsername(e.target.value);
                        }}
                      />
                    </FormControl>
                    {isCheckingUsername && (
                      <FormDescription>Loading....</FormDescription>
                    )}
                    {usernameMessage && (
                      <FormDescription
                        className={`${!isUsernameUnique && "text-red-500"}`}
                      >
                        {usernameMessage}
                      </FormDescription>
                    )}
                    <FormMessage />
                  </FormItem>
                )}
              />
            </DivFadeIn>
            <DivFadeIn initial={5}>
              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email</FormLabel>
                    <FormControl>
                      <Input
                        type="email"
                        placeholder="whoisthis@whoknows.com"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </DivFadeIn>
            <DivFadeIn initial={5}>
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder="tinysecrete"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </DivFadeIn>
            <DivFadeIn initial={2}>
              <Button
                type="submit"
                disabled={isSubmitting}
                className="w-full cursor-pointer"
              >
                {isSubmitting ? "Loading...." : "Sign Up"}
              </Button>
            </DivFadeIn>
          </form>
        </Form>
        <div className="text-center mt-4">
          <p className="text-xs text-neutral-400">
            Already a member?{" "}
            <Link href="/signin" className="text-neutral-300 underline">
              Sign In
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default SignUp;

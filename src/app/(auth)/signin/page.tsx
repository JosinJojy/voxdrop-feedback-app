"use client";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { signInSchema } from "@/schemas/signInSchema";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { GithubIcon } from "lucide-react";
import GoogleIcon from "@/components/ui/GoogleIcon";
import AnimateText from "@/components/custom/animations/AnimateText";
import DivFadeIn from "@/components/custom/animations/DivFadeIn";

const SignIn = () => {
  const [isSubmitting, setIsSubmitting] = useState(false);

  const router = useRouter();

  const form = useForm<z.infer<typeof signInSchema>>({
    resolver: zodResolver(signInSchema),
    defaultValues: {
      identifier: "",
      password: "",
    },
  });

  const onSubmit = async (data: z.infer<typeof signInSchema>) => {
    setIsSubmitting(true);
    const result = await signIn("credentials", {
      redirect: false,
      identifier: data.identifier,
      password: data.password,
    });
    if (result?.error) {
      if (result.error === "CredentialsSignin") {
        toast.error("Sign In failed", {
          description: "Incorect username or password",
          position: "top-center",
        });
      } else {
        toast.error("Sign In failed", {
          description: result.error,
          position: "top-center",
        });
      }
      setIsSubmitting(false);
    }
    if (result?.url) {
      toast.success("Sign In Success", {
        description: "You can now enjoy anonymous feedback",
        position: "top-center",
      });
      router.replace("/dashboard");
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
            Ready To Get Feedback
          </AnimateText>
          <AnimateText className="mb-4 text-neutral-300">
            Sign in to know what others say
          </AnimateText>
        </div>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <DivFadeIn initial={5}>
              <FormField
                control={form.control}
                name="identifier"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Identifier</FormLabel>
                    <FormControl>
                      <Input
                        type="text"
                        placeholder="username or email"
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
                {isSubmitting ? "Loading...." : "Sign In"}
              </Button>
            </DivFadeIn>
            <div className="after:border-border relative text-center text-sm after:absolute after:inset-0 after:top-1/2 after:z-0 after:flex after:items-center after:border-t">
              <span className="bg-card text-muted-foreground relative z-10 px-2 rounded-sm">
                Or continue with
              </span>
            </div>
          </form>
        </Form>
        <DivFadeIn className="grid grid-cols-2 gap-2 w-full" initial={5}>
          <Button
            onClick={() => signIn("github")}
            variant={"outline"}
            className="cursor-pointer active:border-primary"
          >
            <GithubIcon />
            Github
          </Button>
          <Button
            onClick={() => signIn("google")}
            variant={"outline"}
            className="cursor-pointer border focus:!border-primary"
          >
            <GoogleIcon />
            Google
          </Button>
        </DivFadeIn>
        <div className="text-center mt-2">
          <p className="text-xs text-neutral-400">
            Dont have an account?{" "}
            <Link href="/signup" className="text-neutral-300 underline">
              Sign Up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default SignIn;

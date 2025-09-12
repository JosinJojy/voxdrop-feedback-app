import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Zap, Users, ArrowRight } from "lucide-react";
import Footer from "@/components/custom/Footer";
import AnimateText from "@/components/custom/animations/AnimateText";
import DivFadeIn from "@/components/custom/animations/DivFadeIn";
export default function Home() {
  return (
    <div>
      {/* Hero Section */}
      <section className="relative py-20 lg:py-32 bg-gradient-to-br from-primary/10 via-background to-secondary/10 ">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 mt-8">
          <div className="text-center max-w-4xl mx-auto">
            <Badge variant="outline" className="mb-4">
              ✨ Anonymous & Secure
            </Badge>
            {/* I changed something here */}
            <AnimateText
              className="text-4xl lg:text-6xl font-bold tracking-tight mb-6"
              isHeading={true}
            >
              Collect honest feedback
              <span className="text-primary"> anonymously</span>
            </AnimateText>
            <AnimateText className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto">
              Create your feedback link in seconds and start receiving genuine,
              anonymous feedback from your team, customers, or community.
            </AnimateText>
            <DivFadeIn className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <Button size="lg" asChild className="text-lg px-8">
                <Link href="/dashboard">
                  Get Started Free
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Link>
              </Button>
              {/* <Button
                size="lg"
                variant="outline"
                asChild
                className="text-lg px-8"
              >
                <Link href="#howItWorks">View Demo</Link>
              </Button> */}
            </DivFadeIn>
          </div>
        </div>
      </section>

      {/* Festures section */}
      <section className="py-20 lg:py-32">
        <div className="container mx-auto px-4 sm:px-6 lg:px-16">
          <div className="text-center mb-16">
            <AnimateText
              className="text-3xl lg:text-4xl font-bold mb-4"
              isHeading={true}
            >
              Why choose FeedbackHub?
            </AnimateText>
            <AnimateText className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Simple, secure, and effective feedback collection that respects
              privacy
            </AnimateText>
          </div>

          <DivFadeIn className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <Card className="border-2 hover:border-primary/50 transition duration-200">
              <CardHeader>
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4">
                  <Shield className="h-6 w-6 text-primary" />
                </div>
                <CardTitle>100% Anonymous</CardTitle>
                <CardDescription>
                  Complete privacy protection. No tracking, no personal data
                  collection.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="border-2 hover:border-primary/50 transition duration-200">
              <CardHeader>
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4">
                  <Zap className="h-6 w-6 text-primary" />
                </div>
                <CardTitle>Quick Setup</CardTitle>
                <CardDescription>
                  Create your feedback link in under 30 seconds. No complex
                  setup required.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="border-2 hover:border-primary/50 transition duration-200">
              <CardHeader>
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4">
                  <Users className="h-6 w-6 text-primary" />
                </div>
                <CardTitle>Team Friendly</CardTitle>
                <CardDescription>
                  Perfect for teams, organizations, and communities of any size.
                </CardDescription>
              </CardHeader>
            </Card>
          </DivFadeIn>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="howItWorks" className="py-20 lg:py-32 bg-secondary/20">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <AnimateText
              className="text-3xl lg:text-4xl font-bold mb-4"
              isHeading={true}
            >
              How it works
            </AnimateText>
            <AnimateText className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Three simple steps to start collecting valuable feedback
            </AnimateText>
          </div>

          <DivFadeIn className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="w-16 h-16 bg-primary rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-2xl font-bold text-primary-foreground">
                  1
                </span>
              </div>
              <h3 className="text-xl font-semibold mb-4">Create Your Link</h3>
              <p className="text-muted-foreground">
                Sign up and create a personalized feedback link in seconds
              </p>
            </div>

            <div className="text-center">
              <div className="w-16 h-16 bg-primary rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-2xl font-bold text-primary-foreground">
                  2
                </span>
              </div>
              <h3 className="text-xl font-semibold mb-4">Share & Collect</h3>
              <p className="text-muted-foreground">
                Share your link with your team, customers, or community
              </p>
            </div>

            <div className="text-center">
              <div className="w-16 h-16 bg-primary rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-2xl font-bold text-primary-foreground">
                  3
                </span>
              </div>
              <h3 className="text-xl font-semibold mb-4">Review & Improve</h3>
              <p className="text-muted-foreground">
                View all feedback in your dashboard and make improvements
              </p>
            </div>
          </DivFadeIn>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 lg:py-32 dark:bg-neutral-900 bg-neutral-100 dark:text-primary-foreground">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <AnimateText
            className="text-3xl lg:text-4xl font-bold mb-6"
            isHeading={true}
          >
            Ready to start collecting feedback
          </AnimateText>
          <AnimateText className="text-xl mb-8 max-w-2xl mx-auto opacity-90">
            Join thousands of teams who trust FeedbackHub for their feedback
            collection needs
          </AnimateText>
          <DivFadeIn>
            <Button
              size="lg"
              variant="secondary"
              asChild
              className="text-lg px-8"
            >
              <Link href="/dashboard">
                Get Started Free
                <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
            </Button>
          </DivFadeIn>
        </div>
      </section>

      <Footer />
    </div>
  );
}

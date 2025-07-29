import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { CheckCircle2, Shield } from "lucide-react";

const SubmitSuccessMessage = ({
  addNewFeedback,
}: {
  addNewFeedback: () => void;
}) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary/5 via-background to-secondary/5">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="max-w-2xl mx-auto">
          <Card className="text-center border-2 border-green-200 dark:border-green-800 shadow-2xl[ bg-[#00e50014]">
            <CardContent className="pt-12 pb-12">
              <div className="relative mb-8">
                <div className="w-24 h-24 bg-gradient-to-br from-green-400 to-green-600 rounded-full flex items-center justify-center mx-auto mb-6 shadow-lg">
                  <CheckCircle2 className="h-12 w-12 text-white" />
                </div>
                <div className="absolute inset-0 bg-green-400/20 rounded-full blur-xl w-24 h-24 mx-auto animate-pulse" />
              </div>

              <h1 className="text-3xl font-bold mb-4 bg-gradient-to-r from-green-600 to-green-800 bg-clip-text text-transparent">
                Thank You!
              </h1>
              <p className="text-lg text-muted-foreground mb-8 leading-relaxed">
                Your feedback has been submitted successfully and will help
                improve future experiences. Your voice matters and contributes
                to positive change.
              </p>

              <div className="bg-gradient-to-r from-green-50 to-emerald-50 dark:from-green-950 dark:to-emerald-950 p-6 rounded-xl border border-green-200 dark:border-green-800 mb-8">
                <div className="flex items-center justify-center space-x-3 text-green-700 dark:text-green-300">
                  <Shield className="h-6 w-6" />
                  <span className="font-semibold text-lg">
                    Your identity remains completely anonymous
                  </span>
                </div>
                <p className="text-sm text-green-600 dark:text-green-400 mt-2">
                  No personal information was collected or stored during this
                  submission
                </p>
              </div>

              <div className="text-center">
                <p className="text-sm text-muted-foreground mb-4">
                  Want to submit more feedback?
                </p>
                <Button
                  onClick={() => {
                    addNewFeedback();
                  }}
                  variant="outline"
                  className="hover:bg-primary hover:text-primary-foreground transition-all duration-300"
                >
                  Submit Another Response
                </Button>
              </div>
            </CardContent>
          </Card>

          <div className="text-center mt-8">
            <p className="text-sm text-muted-foreground">
              Powered by{" "}
              <span className="font-semibold text-primary">FeedbackHub</span> •
              <span className="ml-2">Secure • Anonymous • Trusted</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SubmitSuccessMessage;

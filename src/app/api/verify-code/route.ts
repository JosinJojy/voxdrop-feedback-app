import { NextRequest, NextResponse } from "next/server";
import dbConnect from "@/lib/dbConnect";
import UserModel, { Feedback, FeedbackCategory } from "@/models/UserModel";
import { initialFeedbackFromDeveloper } from "@/helpers/feedback-card-helpers";

export async function POST(request: NextRequest) {
  await dbConnect();

  try {
    const { username, code } = await request.json();
    const decodedUsername = decodeURIComponent(username);

    const user = await UserModel.findOne({
      username: decodedUsername,
    });

    if (!user) {
      return NextResponse.json(
        {
          success: false,
          message: "No user found ",
        },
        { status: 400 }
      );
    }

    const isCodeCorrect = user.verifyCode === code;
    const isCodeNotExpired =
      user.verifyCodeExpiry && new Date(user.verifyCodeExpiry) > new Date();

    if (isCodeCorrect && isCodeNotExpired) {
      user.isVerified = true;
      user.verifyCode = undefined;
      user.verifyCodeExpiry = undefined;
      // await user.save();

      // Add sample category for new user
      const newFeedbackCategory = {
        title: "Ask me Anything",
        createdAt: new Date(),
        isAcceptingThisCategory: true,
        userId: user._id,
        count: 0,
      };

      user.FeedbackCategories?.push(newFeedbackCategory as FeedbackCategory);
      const lastCategory =
        user.FeedbackCategories &&
        user.FeedbackCategories[user.FeedbackCategories.length - 1];

      //senda a sample feedback to new user
      const newFeedback = {
        content: initialFeedbackFromDeveloper,
        createdAt: new Date(),
        feedbackCategoryId: lastCategory && lastCategory._id,
        feedbackCategoryTitle: "Ask me Anything",
        feedbackType: "positive",
      };

      user.feedbacks.push(newFeedback as Feedback);
      await user.save();

      return NextResponse.json(
        {
          success: true,
          message: "user verified successfully",
        },
        { status: 201 }
      );
    }

    if (isCodeCorrect && !isCodeNotExpired) {
      return NextResponse.json(
        {
          success: false,
          message:
            "Verification code expired, sign-in again with the same eamil or username",
        },
        { status: 400 }
      );
    }

    if (!isCodeCorrect) {
      return NextResponse.json(
        {
          success: false,
          message: "Invalid verification code",
        },
        { status: 400 }
      );
    }
  } catch (error) {
    console.log(error);
    return NextResponse.json(
      {
        success: false,
        message: "Error Verifying verification code",
      },
      { status: 500 }
    );
  }
}

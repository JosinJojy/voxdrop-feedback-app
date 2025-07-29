import { NextRequest, NextResponse } from "next/server";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/UserModel";
import { Feedback } from "@/models/UserModel";
import mongoose from "mongoose";

export async function POST(request: NextRequest) {
  await dbConnect();

  const {
    userId,
    content,
    feedbackCategoryId,
    feedbackCategoryTitle,
    feedbackType,
  } = await request.json();

  try {
    const user = await UserModel.findById(userId);
    if (!user) {
      return NextResponse.json(
        {
          success: false,
          message: "No user found ",
        },
        { status: 404 }
      );
    }

    const isFeedbackAccepted = await UserModel.findOne({
      _id: new mongoose.Types.ObjectId(userId!),
      FeedbackCategories: {
        $elemMatch: {
          _id: new mongoose.Types.ObjectId(feedbackCategoryId),
          isAcceptingThisCategory: true,
        },
      },
    });

    if (!isFeedbackAccepted) {
      return NextResponse.json(
        {
          success: false,
          message: "User is not accepting feedbacks from this category",
        },
        { status: 403 }
      );
    }

    const newFeedback = {
      content,
      createdAt: new Date(),
      feedbackCategoryId,
      feedbackCategoryTitle,
      feedbackType,
    };

    user.feedbacks.push(newFeedback as Feedback);
    await user.save();

    await UserModel.updateOne(
      {
        _id: userId,
        "FeedbackCategories._id": feedbackCategoryId,
      },
      {
        $inc: {
          "FeedbackCategories.$.count": 1,
        },
      }
    );

    return NextResponse.json(
      {
        success: true,
        message: "Message send successfully",
      },
      { status: 200 }
    );
  } catch (error) {
    console.log("Error sending messages", error);
    return NextResponse.json(
      {
        success: false,
        message: "Error sending message",
      },
      { status: 500 }
    );
  }
}

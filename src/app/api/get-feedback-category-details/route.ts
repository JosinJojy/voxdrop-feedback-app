import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/UserModel";
import mongoose from "mongoose";
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {

  await dbConnect();
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get("userId");
  const feedbackCategoryId = searchParams.get("feedbackCategoryId");

  try {
    const user = await UserModel.findOne(
      {
        _id: new mongoose.Types.ObjectId(userId!),
        "FeedbackCategories._id": new mongoose.Types.ObjectId(
          feedbackCategoryId!
        ),
      },
      {
        "FeedbackCategories.$": 1, // Projects only the matching subdocument
      }
    );
    if (!user) {
      return NextResponse.json(
        {
          success: false,
          message: "User not found",
        },
        { status: 403 }
      );
    }
    return NextResponse.json(
      {
        success: true,
        feedbackCategoryDetails: user.FeedbackCategories,
      },
      { status: 201 }
    );
  } catch (error) {
    console.log("Error getting feedback details", error);
    return NextResponse.json(
      {
        success: false,
        message: "Error getting feedback details",
      },
      { status: 500 }
    );
  }
}

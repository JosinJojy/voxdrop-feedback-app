import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "../../../lib/auth";
import dbConnect from "@/lib/dbConnect";
import UserModel, { FeedbackCategory } from "@/models/UserModel";
import { User } from "next-auth";

export async function POST(request: NextRequest) {
  await dbConnect();
  const session = await getServerSession(authOptions);
  const user: User = session?.user as User;

  if (!session || !session.user) {
    return NextResponse.json(
      {
        success: false,
        message: "No user found ",
      },
      { status: 404 }
    );
  }

  const { feedbackCategoryTitle, userId } = await request.json();

  try {
    const existingUser = await UserModel.findById(user._id);
    if (!existingUser) {
      return NextResponse.json(
        {
          success: false,
          message: "No user found ",
        },
        { status: 404 }
      );
    }

    const newFeedbackCategory = {
      title: feedbackCategoryTitle,
      createdAt: new Date(),
      isAcceptingThisCategory: true,
      userId: userId.toString(),
      count: 0
    };

    existingUser.FeedbackCategories?.push(
      newFeedbackCategory as FeedbackCategory
    );

    await existingUser.save();

    return NextResponse.json(
      {
        success: true,
        message: " New feedback category added successfully",
      },
      { status: 200 }
    );
  } catch (error) {
    console.log("Error adding new feedback category", error);
    return NextResponse.json(
      {
        success: false,
        message: "Error adding new feedback category",
      },
      { status: 500 }
    );
  }
}

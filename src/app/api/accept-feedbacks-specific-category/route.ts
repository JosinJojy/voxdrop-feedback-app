import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "../../../lib/auth";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/UserModel";
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

  const userId = user._id;
  const { acceptFeedbacks, feedbackCategoryId } = await request.json();

  try {
    const updatedUser = await UserModel.updateOne(
      {
        _id: userId,
        "FeedbackCategories._id": feedbackCategoryId,
      },
      {
        $set: {
          "FeedbackCategories.$.isAcceptingThisCategory": acceptFeedbacks,
        },
      }
    );

    if (!updatedUser) {
      return NextResponse.json(
        {
          success: false,
          message: "Failed to find user ",
        },
        { status: 404 }
      );
    }

    return NextResponse.json(
      {
        success: true,
        message: "Message acceptance status updated successfully",
      },
      { status: 201 }
    );
  } catch (error) {
    console.log("Failed to update user status to accept messages", error);
    return NextResponse.json(
      {
        success: false,
        message: "Failed to update user status to accept messages ",
      },
      { status: 500 }
    );
  }
}

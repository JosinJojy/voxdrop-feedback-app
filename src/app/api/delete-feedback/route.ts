/* eslint-disable @typescript-eslint/no-explicit-any */
import dbConnect from "@/lib/dbConnect";
import { getServerSession, User } from "next-auth";
import { NextRequest, NextResponse } from "next/server";
import UserModel from "@/models/UserModel";
import { authOptions } from "@/lib/auth";

export async function DELETE(request: NextRequest) {
  await dbConnect();

  const { searchParams } = new URL(request.url);
  const messageId = searchParams.get("feedbackId");
  const categoryId = searchParams.get("categoryId");

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

  try {
    const updatedResult = await UserModel.findByIdAndUpdate(user._id, {
      $pull: {
        feedbacks: {
          _id: messageId,
        },
      },
    });

    if (!updatedResult?.isModified) {
      return NextResponse.json(
        {
          success: false,
          message: "Message not found or already deleted",
        },
        { status: 401 }
      );
    }

    await UserModel.updateOne(
      {
        _id: user._id,
        "FeedbackCategories._id": categoryId,
      },
      {
        $inc: {
          "FeedbackCategories.$.count": -1,
        },
      }
    );

    return NextResponse.json(
      {
        success: true,
        message: "Message deleted successfully",
      },
      { status: 200 }
    );
  } catch (error) {
    console.error("Error deleting message ", error);
    return NextResponse.json(
      {
        success: false,
        message: "Error deleting message",
      },
      { status: 500 }
    );
  }
}

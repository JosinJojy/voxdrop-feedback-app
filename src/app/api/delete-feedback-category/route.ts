import dbConnect from "@/lib/dbConnect";
import { getServerSession, User } from "next-auth";
import { NextRequest, NextResponse } from "next/server";
import UserModel from "@/models/UserModel";
import { authOptions } from "@/lib/auth";

export async function DELETE(request: NextRequest) {
  await dbConnect();

  const { searchParams } = new URL(request.url);
  const categoryId = searchParams.get("categoryId");
  console.log("Message Id from delete =", categoryId);

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
    const existingUser = await UserModel.findByIdAndUpdate(user?._id, {
      $pull: {
        FeedbackCategories: {
          _id: categoryId,
        },
        feedbacks:{
          feedbackCategoryId: categoryId
        }
      },
    });

    if (!existingUser?.isModified) {
      return NextResponse.json(
        {
          success: false,
          message: "Feedback category not found or already deleted",
        },
        { status: 401 }
      );
    }
    return NextResponse.json(
      {
        success: true,
        message: "Feedback category deleted successfully",
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

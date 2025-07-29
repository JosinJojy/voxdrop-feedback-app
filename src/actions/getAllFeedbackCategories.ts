"use server";
import { authOptions } from "@/lib/auth";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/UserModel";
import { getServerSession } from "next-auth";

export const getAllFeedbackCategories = async () => {
  await dbConnect();
  const session = await getServerSession(authOptions);
  const userId = session?.user?._id;

  if (!session || !session.user) {
    return {
      success: false,
      AllCategories: [],
    };
  }

  try {
    const existingUser = await UserModel.findById(userId, { messages: 0 });
    if (!existingUser) {
      return;
    }
    const AllCategories = existingUser.FeedbackCategories;
    return {
      success: true,
      AllCategories: AllCategories?.map((category) => ({
        _id: category._id?.toString(),
        title: category.title,
      })),
    };
  } catch (error) {
    console.log("Error getting all geedback categories ", error);
    return {
      success: true,
      AllCategories: [],
    };
  }
};

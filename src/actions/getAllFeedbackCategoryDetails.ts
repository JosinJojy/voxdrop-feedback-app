"use server";
import dbConnect from "@/lib/dbConnect";
import UserModel, { FeedbackCategory } from "@/models/UserModel";
import mongoose from "mongoose";

export const getAllFeedbackCategoryDetails = async (userId: string) => {
  if (!userId) return [];
  await dbConnect();
  try {
    const response = await UserModel.aggregate([
      {
        $match: {
          _id: new mongoose.Types.ObjectId(userId),
        },
      },
      {
        $project: {
          FeedbackCategories: {
            $sortArray: {
              input: "$FeedbackCategories",
              sortBy: {
                createdAt: -1,
              },
            },
          },
        },
      },
    ]);
    return (
      response[0]?.FeedbackCategories?.map(
        (feedbackCategory: FeedbackCategory) => ({
          _id: feedbackCategory._id?.toString(),
          title: feedbackCategory.title,
          createdAt: feedbackCategory.createdAt,
          isAcceptingThisCategory: feedbackCategory.isAcceptingThisCategory,
          userId: feedbackCategory.userId.toString(),
          count: feedbackCategory.count
        })
      ) || []
    );
  } catch (error) {
    console.log(
      "Some error occured in getting All Feedback Category Details ",
      error
    );
    return [];
  }
};

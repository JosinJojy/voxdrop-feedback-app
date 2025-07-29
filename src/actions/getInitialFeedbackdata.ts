import { authOptions } from "@/lib/auth";
import dbConnect from "@/lib/dbConnect";
import UserModel, { Feedback } from "@/models/UserModel";
import mongoose from "mongoose";
import { getServerSession, User } from "next-auth";

export const getInitialFeedbacks = async () => {
  await dbConnect();
  try {
    const session = await getServerSession(authOptions);
    const user: User = session?.user as User;
    const userId = new mongoose.Types.ObjectId(user._id);

    if (!session || !user) return;

    const limit = 5;

    const existingUser = await UserModel.aggregate([
      {
        $match: {
          _id: userId,
        },
      },
      {
        $unwind: "$feedbacks",
      },
      {
        $sort: {
          "feedbacks.createdAt": -1,
        },
      },
      {
        $limit: limit + 1,
      },
      {
        $group: {
          _id: "$_id",
          feedbacks: { $push: "$feedbacks" },
        },
      },
    ]);
    const hasmore = existingUser[0]?.feedbacks?.length > limit;

    return {
      success: true,
      feedbacks:
        existingUser[0]?.feedbacks.length > 0
          ? existingUser[0]?.feedbacks.slice(0, limit).map((msg: Feedback) => ({
              _id: msg._id?.toString(),
              content: msg.content,
              createdAt: msg.createdAt
                ?.toString()
                .split(" ")
                .slice(0, 4)
                .join(" "),
              feedbackCategoryId: msg.feedbackCategoryId?.toString(),
              feedbackCategoryTitle: msg.feedbackCategoryTitle,
              feedbackType: msg.feedbackType,
            }))
          : [],
      nextPage: hasmore ? 2 : undefined,
    };
  } catch (error) {
    console.log(
      "\nError fetching the initial Feedbacks for react query =",
      error
    );
  }
};

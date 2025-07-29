/* eslint-disable @typescript-eslint/no-explicit-any */
import { authOptions } from "@/lib/auth";
import dbConnect from "@/lib/dbConnect";
import UserModel, { Feedback } from "@/models/UserModel";
import mongoose from "mongoose";
import { getServerSession, User } from "next-auth";
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  
  const { searchParams } = new URL(request.url);
  const pageNumber = searchParams.get("page");
  const categoryId = searchParams.get("categoryId");
  const type = searchParams.get("type");

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

  const userId = new mongoose.Types.ObjectId(user._id);

  const limit = 5;
  const skip = (parseInt(pageNumber || "1") - 1) * limit;

  const pipeline: any[] = [
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
      $skip: skip,
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
  ];

  const isValidCategory = categoryId && categoryId !== "All Categories";
  const isValidType = type && type !== "All Types";

  const matchConditions: Record<string, any> = {};

  if (isValidCategory) {
    matchConditions["feedbacks.feedbackCategoryId"] =
      new mongoose.Types.ObjectId(categoryId);
  }

  if (isValidType) {
    matchConditions["feedbacks.feedbackType"] = type;
  }

  if (Object.keys(matchConditions).length > 0) {
    pipeline.splice(2, 0, {
      $match: matchConditions,
    });
  }

  try {
    const user = await UserModel.aggregate(pipeline);

    if (!user) {
      return NextResponse.json(
        {
          success: false,
          feedbacks: [],
        },
        { status: 401 }
      );
    }
    const hasmore = user[0]?.feedbacks?.length > limit;

    return NextResponse.json(
      {
        success: true,
        feedbacks:
          user[0]?.feedbacks.length > 0
            ? user[0]?.feedbacks.slice(0, limit).map((msg: Feedback) => ({
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
        nextPage: hasmore ? parseInt(pageNumber || "1") + 1 : undefined,
      },
      { status: 200 }
    );
  } catch (error) {
    console.log("Some error occured while getting all Feedbacks ", error);
    return NextResponse.json(
      {
        success: false,
        feedbacks: [],
      },
      { status: 500 }
    );
  }
}

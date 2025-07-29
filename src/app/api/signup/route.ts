import { NextRequest, NextResponse } from "next/server";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/UserModel";
import bcrypt from "bcryptjs";
import { sendVerificationEmail } from "@/helpers/sendVerificationEmail";

export async function POST(request: NextRequest) {
  await dbConnect();
  try {
    const { username, email, password } = await request.json();

    const existingUserWithUserNameVerified = await UserModel.findOne({
      username,
      isVerified: true,
    });

    if (existingUserWithUserNameVerified) {
      return NextResponse.json(
        { success: false, message: "Username already exists" },
        { status: 400 }
      );
    }

    const existingUserWithEmail = await UserModel.findOne({ email });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const verifyCode = Math.floor(Math.random() * 1000000).toString();
    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 1);

    if (existingUserWithEmail) {
      if (existingUserWithEmail.isVerified) {
        return NextResponse.json(
          { success: false, message: "email already exists" },
          { status: 400 }
        );
      } else {
        existingUserWithEmail.username = username;
        existingUserWithEmail.password = hashedPassword;
        existingUserWithEmail.verifyCode = verifyCode;
        existingUserWithEmail.verifyCodeExpiry = expiryDate;
        existingUserWithEmail.isVerified = false;

        await existingUserWithEmail.save();
      }
    } else {
      const newUser = await UserModel.create({
        username,
        email,
        password: hashedPassword,
        verifyCode,
        verifyCodeExpiry: expiryDate,
        isVerified: false,
        isAcceptingMessage: true,
        messages: [],
      });
      console.log(newUser) // TODO rEVIEW THIS PART
    }

    const emailResponse = await sendVerificationEmail(
      email,
      username,
      verifyCode
    );

    if (emailResponse.success) {
      console.log("\n\nUser created successfully and a verification link is send to him\n\n")
      return NextResponse.json(
        {
          success: true,
          message: "User created successfully , please verify your email",
        },
        { status: 201 }
      );
    } else {
      return NextResponse.json(
        { success: false, message: emailResponse.message },
        { status: 400 }
      );
    }
  } catch (error) {
    console.error("Error registering the user", error);
    return NextResponse.json(
      { success: false, message: "Error registering the user" },
      { status: 500 }
    );
  }
}

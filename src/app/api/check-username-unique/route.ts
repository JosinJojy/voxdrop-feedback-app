import { NextRequest, NextResponse } from "next/server";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/UserModel";
import { usernameValidation } from "@/schemas/signUpSchema";


export async function GET(request: NextRequest) {
    await dbConnect()

    try {

        const username = request.nextUrl.searchParams.get("username");

        const validationResult = usernameValidation.safeParse(username);
        
        if(!validationResult.success){

            const usernameErrors = validationResult.error.format()._errors || []
            return NextResponse.json({
                success:false,
                message: usernameErrors.length > 0 ? usernameErrors.join(", ") : 'Invalid query parameters'
            }, {status: 400})
        }

        const existingVerifiedUser = await UserModel.findOne({username, isVerified:true})

        if(existingVerifiedUser){
            return NextResponse.json({
                success:false,
                message: "username already exists"
            }, {status: 400})
        }

        return NextResponse.json({
            success:true,
            message: "username awailable"
        }, {status: 201})

    } catch (error) {

        console.error("Error checking username ",error)
        return NextResponse.json({
            success:false,
            message: "Error checking username"
        }, {status: 500})
    }
}
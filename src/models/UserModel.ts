import mongoose, {Schema, Document, Types} from "mongoose";

export interface Feedback extends Document {
    content: string,
    createdAt: Date | string,
    feedbackCategoryId: Types.ObjectId,
    feedbackCategoryTitle: string,
    feedbackType:string,
}


export const FeedbackSchema: Schema<Feedback> = new Schema({
    content:{
        type:String,
        required: true
    },
    createdAt:{
        type:Date,
        required:true,
        default:Date.now
    },
    feedbackCategoryId:{
        type: mongoose.Schema.Types.ObjectId
    },
    feedbackCategoryTitle:{
        type:String,
    },
    feedbackType:{
        type:String,
        default:"general"
    }
})

export interface FeedbackCategory extends Document {
    title:string;
    createdAt:Date;
    isAcceptingThisCategory:boolean;
    userId:string;
    count: number | undefined
}

const FeedbackCategorySchema: Schema<FeedbackCategory> = new Schema({
    title:{
        type:String,
        required:true
    },
    createdAt:{
        type:Date,
        required:true,
        default:Date.now
    },
    isAcceptingThisCategory:{
        type: Boolean,
        default:true
    },
    userId:{
        type: String,
        required:true
    },
    count:{
        type: Number,
        default:0,
        required:true
    }
})

export interface User extends Document {
    username: string;
    email: string;
    password: string;
    verifyCode?: string | undefined;
    verifyCodeExpiry?: Date | undefined;
    isVerified:boolean;
    feedbacks: Feedback[],
    FeedbackCategories?: FeedbackCategory[]
}

const UserSchema: Schema<User> = new Schema({
    username:{
        type: String,
        required: [true, "username is required"],
        trim: true,
        unique: true
    },
    email:{
        type: String,
        required: [true, "email is required"],
        unique: true,
        match: [/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/g, "Please use a valid email"]
    },
    password:{
        type: String,
    },
    verifyCode:{
        type: String,
        required: false
    },
    verifyCodeExpiry:{
        type: Date,
        required: false
    },
    isVerified:{
        type: Boolean,
        required: false
    },
    feedbacks: [FeedbackSchema],
    FeedbackCategories: [FeedbackCategorySchema]

})


const UserModel = mongoose.models.User as mongoose.Model<User> || mongoose.model<User>("User", UserSchema)

export default UserModel
import { NextAuthOptions, User } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GitHubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import bcrypt from "bcryptjs";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/models/UserModel";

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Credentials",
      credentials: {
        identifier: { label: "Username or Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(
        credentials: Record<"identifier" | "password", string> | undefined
      ): Promise<User | null> {
        await dbConnect();
        try {
          const user = await UserModel.findOne({
            $or: [
              { username: credentials?.identifier },
              { email: credentials?.identifier },
            ],
          });

          if (!user) {
            throw new Error("No user found with this email");
          }
          if (!user.isVerified) {
            throw new Error("Please verify your account before login");
          }

          const isPasswordCorrect = await bcrypt.compare(
            credentials?.password || "",
            user.password
          );
          if (isPasswordCorrect) {
            return user as any; // eslint-disable-line @typescript-eslint/no-explicit-any
          } else {
            throw new Error("Wrong password");
          }
        } catch (error: unknown) {
          if (error instanceof Error) {
            throw new Error(error.message);
          }
          throw new Error("Unknown error occurred");
        }
      },
    }),

    GitHubProvider({
      clientId: process.env.GITHUB_ID!,
      clientSecret: process.env.GITHUB_SECRET!,
    }),

    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
  ],

  pages: {
    signIn: "/signin",
  },

  session: {
    strategy: "jwt",
  },

  secret: process.env.NEXTAUTH_SECRET,

  callbacks: {
    async jwt({ token, user, account, profile }) {
      if (user) {
        //auth by credentials
        token._id = user._id?.toString();
        token.username = user.username;
        token.isVerified = user.isVerified;
      }

      if (account && profile) {
        //auth by google or github
        await dbConnect();
        let exsistingUser = await UserModel.findOne({ email: profile.email });
        if (!exsistingUser) {
          const newUser = await UserModel.create({
            username: profile.name || profile.email?.split("@")[0],
            email: profile.email,
            isVerified: true,
          });

          // Add sample category for new user
          // const newFeedbackCategory = {
          //   title: "Ask me Anything",
          //   createdAt: new Date(),
          //   isAcceptingThisCategory: true,
          //   userId: newUser?._id,
          //   count: 0,
          // };
          // console.log("\n\n\n\\\\n",newFeedbackCategory)
          exsistingUser = newUser;
        }

        token._id = exsistingUser._id?.toString();
        token.username = exsistingUser.username;
        token.email = exsistingUser.email;
        token.isVerified = true;
      }

      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user._id = token._id;
        session.user.username = token.username;
        session.user.isVerified = token.isVerified;
      }
      return session;
    },
  },
};

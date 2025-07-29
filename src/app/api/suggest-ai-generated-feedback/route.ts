import { NextRequest } from "next/server";
import {
  GoogleGenerativeAI,
  GoogleGenerativeAIError,
} from "@google/generative-ai";


export const runtime = "nodejs";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY!);

export async function GET(request: NextRequest) {
  console.log(request.json)
  const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

  const randomThemes = [
    "hobbies",
    "travel",
    "personal growth",
    "entertainment",
    "coding",
    "programming",
    "future goals",
    "books",
    "relationships",
    "cricket",
    "memes",
    "personal questions",
  ];

  const randomTheme =
    randomThemes[Math.floor(Math.random() * randomThemes.length)];
  const prompt = `Create a list of three unique and short question words range 10-15, open-ended, and engaging questions focusing on the theme of "${randomTheme}". Each question should be separated by '¤'. These questions are for an anonymous social messaging platform like Qooh.me. Avoid personal or sensitive topics, and ensure the questions encourage interaction, curiosity, and positivity.`;

  const encoder = new TextEncoder();
  
  const stream = new ReadableStream({
    async start(controller) {
      try {
        const result = await model.generateContentStream(prompt);
        for await (const chunk of result.stream) {
          const text = chunk.text();
          controller.enqueue(encoder.encode(text));
        }
        controller.close();
      } catch (error) {
        if (error instanceof GoogleGenerativeAIError) {
          console.log("Gemini Error =", error.message);
        } else {
          console.log("An unexpected error occured");
        }
      }
    },
  });

   return new Response(stream, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
}

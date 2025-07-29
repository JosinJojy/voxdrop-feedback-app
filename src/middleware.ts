import { NextResponse, NextRequest } from "next/server";
export { default } from "next-auth/middleware";
import { getToken } from "next-auth/jwt";

export async function middleware(request: NextRequest) {
  const token = await getToken({ req: request });
  const url = request.nextUrl.pathname;

  const isPublicPath =
    url.startsWith("/signin") ||
    url.startsWith("/signup") ||
    url.startsWith("/verify") ||
    url === '/'

  if (isPublicPath && token) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  if (!isPublicPath && !token) {
    return NextResponse.redirect(new URL("/signin", request.nextUrl));
  }
}

export const config = {
  matcher: ["/", "/signin", "/signup", "/dashboard/:path*", "/verify/:path*", ],
};

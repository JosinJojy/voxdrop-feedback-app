"use client";

import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { useSession, signOut } from "next-auth/react";
import { User } from "next-auth";
import Link from "next/link";
import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";
import { User as UsesrIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Separator } from "../ui/separator";
import Image from "next/image";

export default function Navbar() {
  const { data: session } = useSession();
  const user: User = session?.user as User;

  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      const offset = window.scrollY;
      setScrolled(offset > 50);
    };

    window.addEventListener("scroll", handleScroll);

    return () => {
      window.removeEventListener("scroll", handleScroll);
    };
  }, []);

  const { setTheme } = useTheme();

  const pathname = usePathname();
  const [isFeedbacks, setIsFeedbacks] = useState(false);

  useEffect(() => {
    if (pathname?.startsWith("/feedback")) {
      setIsFeedbacks(true);
    } else {
      setIsFeedbacks(false);
    }
  }, [pathname]);

  return (
    <nav
      className={`fixed w-full top-0 z-50 ${scrolled ? "bg-background/80 backdrop-blur-xl shadow-lg" : "bg-transparent"} transition duration-200`}
    >
      <div className="mx-auto max-w-7xl px-4 py-2 sm:px-2 ">
        <div className="flex h-16 justify-between items-center">
          {/* Left section */}
          <div className="flex items-center justify-center gap-2">
            <Image width={50} height={50} alt="" src="voxdrop-logo.svg" />
            <h1 className="hidden sm:block text-3xl font-bold">VOXDROP</h1>
          </div>

          {/* Right section */}
          <div className="flex items-center gap-4">
            {/* Theme selector */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" className="rounded-full">
                  <Sun className="h-[1.2rem] w-[1.2rem] scale-100 rotate-0 transition-all dark:scale-0 dark:-rotate-90" />
                  <Moon className="absolute h-[1.2rem] w-[1.2rem] scale-0 rotate-90 transition-all dark:scale-100 dark:rotate-0" />
                  <span className="sr-only">Toggle theme</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setTheme("light")}>
                  Light
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTheme("dark")}>
                  Dark
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTheme("system")}>
                  System
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            {user ? (
              <div className="flex items-center justify-center gap-2 bg-neutral-200 dark:bg-neutral-800 shadow rounded-full">
                <h1 className="hidden sm:block text-xs px-4 py-2 ">
                  {user?.username || user?.email}
                </h1>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="rounded-full bg-white dark:bg-neutral-900 border overflow-hidden"
                    >
                      <UsesrIcon />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-48">
                    <DropdownMenuItem>Profile</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => signOut()}>
                      Sign out
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            ) : (
              <Link href={"/signin"}>
                <Button className="text-xs sm:text-md">Get started </Button>
              </Link>
            )}
          </div>
        </div>
      </div>
      {!isFeedbacks && <Separator />}
      
    </nav>
  );
}

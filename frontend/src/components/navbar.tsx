"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/utils";

interface NavbarProps {
  showAuth?: boolean;
  showMenu?: boolean;
  onMenuClick?: () => void;
  user?: {
    name: string;
    email: string;
    initials: string;
  };
  onSignIn?: () => void;
  onSignUp?: () => void;
}

export function Navbar({
  showAuth = false,
  showMenu = false,
  onMenuClick,
  user,
  onSignIn,
  onSignUp,
}: NavbarProps) {
  const pathname = usePathname();
  const isHome = pathname === "/";

  return (
    <header
      className={cn(
        "fixed top-0 z-50 w-full bg-white dark:bg-zinc-900 font-montserrat",
        !isHome && "border-b border-zinc-200 dark:border-zinc-800"
      )}
    >
      <div className="mx-auto flex h-14 md:h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
        <div className="flex items-center space-x-2">
          {showMenu && (
            <Button
              variant="ghost"
              size="icon"
              className="mr-2 md:hidden"
              onClick={onMenuClick}
            >
              <Menu className="h-5 w-5" />
            </Button>
          )}
          <Link href="/" className="flex items-center space-x-2">
            <span className="text-lg md:text-xl font-bold text-zinc-900 dark:text-white">
             Argus AI
            </span>
          </Link>
        </div>

        {!user && (
          <nav className="hidden md:flex items-center space-x-1 rounded-full border border-zinc-200 bg-white/50 px-2 py-1 backdrop-blur-sm dark:border-zinc-800 dark:bg-zinc-900/50">
            <Link
              href="/"
              className="rounded-full px-4 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800/50"
            >
              Home
            </Link>
            <Link
              href="#"
              className="rounded-full px-4 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800/50"
            >
              Features
            </Link>
            <Link
              href="#"
              className="rounded-full px-4 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800/50"
            >
              How it Works
            </Link>
            <Link
              href="#"
              className="rounded-full px-4 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800/50"
            >
              About
            </Link>
          </nav>
        )}

        <div className="flex items-center space-x-2 md:space-x-4">
          <ThemeToggle />
          {showAuth ? (
            <div className="flex items-center space-x-2 md:space-x-4">
              <button
                onClick={onSignIn}
                className="rounded-full bg-primary px-3 md:px-4 py-1.5 md:py-2 text-xs md:text-sm font-medium text-primary-foreground hover:bg-primary/90"
              >
                Sign In
              </button>
            </div>
          ) : user ? (
            <div className="flex items-center space-x-2">
              <div className="h-8 w-8 rounded-full bg-zinc-200 dark:bg-zinc-700 flex items-center justify-center">
                <span className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                  {user.initials}
                </span>
              </div>
              <div className="hidden md:flex flex-col">
                <span className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                  {user.name}
                </span>
                <span className="text-xs text-zinc-500 dark:text-zinc-400">
                  {user.email}
                </span>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}
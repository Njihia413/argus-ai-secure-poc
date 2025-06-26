"use client";

import { useState } from "react";
import {Navbar} from "@/components/navbar";
import {FlipText} from "@/registry/magicui/flip-text";
import {TypingAnimation} from "@/components/ui/typing-animation";
import {InteractiveHoverButton} from "@/components/ui/interactive-hover-button";
import {Globe} from "@/registry/magicui/globe";
import {Footer} from "@/components/footer";
import { useRouter } from "next/navigation";
import { siteConfig } from "../config";


export default function Home() {
  const router = useRouter();

  return (
    <div className="relative flex h-screen w-screen flex-col overflow-hidden">
      <Navbar
        showAuth={true}
        onSignIn={() => router.push("/login")}
      />

      {/* Main Content */}
      <main className="flex flex-1 items-center justify-center relative px-4">
        <div className="flex flex-col items-center gap-6 md:gap-10 z-10 max-w-3xl mx-auto">
          <div className="text-center space-y-4 md:space-y-6">
            <h1 className="whitespace-pre-wrap space-y-2 font-space-grotesk">
              <div>
                <FlipText
                  className="pointer-events-none whitespace-pre-wrap bg-gradient-to-b from-black to-gray-400/80 bg-clip-text text-center text-4xl md:text-8xl font-semibold leading-none text-transparent dark:from-white dark:to-slate-900/10"
                  duration={0.7}
                  delayMultiple={0.1}
                >
                  {siteConfig.name}
                </FlipText>
              </div>
              <div>
                <TypingAnimation
                  className="pointer-events-none text-center text-lg md:text-4xl font-medium tracking-wide text-zinc-600 dark:text-zinc-400"
                  duration={50}
                  delay={1000}
                  startOnView={true}
                >
                  {siteConfig.description}
                </TypingAnimation>
              </div>
            </h1>
          </div>

          <div className="mt-4 md:mt-6">
            <InteractiveHoverButton
              onClick={() => router.push("/login")}
              className="border-zinc-200 dark:border-zinc-800 text-sm md:text-base px-6 md:px-8 py-2 md:py-3"
            >
              Get Started
            </InteractiveHoverButton>
          </div>

          <p className="text-center text-sm md:text-lg text-zinc-600 dark:text-zinc-400 max-w-2xl">
            Secure your organization with AI-powered insights and{" "}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-zinc-800 to-zinc-600 dark:from-zinc-200 dark:to-zinc-400">
              proactively manage threats with our intelligent security platform.
            </span>
          </p>
        </div>

        <Globe className="aspect-square mt-62 scale-90 md:scale-110 opacity-80 absolute" />
      </main>

      <Footer />
    </div>
  );
}

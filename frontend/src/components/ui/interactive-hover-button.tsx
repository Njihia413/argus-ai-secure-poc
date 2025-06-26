"use client";

import { useState } from "react";

interface InteractiveHoverButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  className?: string;
}

export function InteractiveHoverButton({
  children,
  onClick,
  className = "",
}: InteractiveHoverButtonProps) {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`relative px-8 py-3 text-lg font-medium transition-all duration-300 rounded-full border ${className} overflow-hidden group`}
    >
      <span className="relative z-10">{children}</span>
      <div
        className={`absolute inset-0 bg-gradient-to-r from-zinc-900 to-zinc-800 dark:from-zinc-100 dark:to-zinc-200 transition-transform duration-300 ${
          isHovered ? "translate-x-0" : "-translate-x-full"
        }`}
      />
    </button>
  );
}
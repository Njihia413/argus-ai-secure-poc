"use client";

import {
  AnimatePresence,
  motion,
  type Variants,
  type MotionProps,
} from "framer-motion";
import { type ElementType } from "react";
import React from "react";

import { cn } from "@/lib/utils";

interface FlipTextProps extends MotionProps {
  /** The duration of the animation */
  duration?: number;
  /** The delay between each character */
  delayMultiple?: number;
  /** The variants of the animation */
  framerProps?: Variants;
  /** The class name of the component */
  className?: string;
  /** The element type of the component */
  as?: ElementType;
  /** The children of the component */
  children: React.ReactNode;
  /** The variants of the animation */
  variants?: Variants;
}

const defaultVariants: Variants = {
  hidden: { rotateX: -90, opacity: 0 },
  visible: { rotateX: 0, opacity: 1 },
};

export function FlipText({
  children,
  duration = 0.5,
  delayMultiple = 0.08,
  className,
  as: Component = "span",
  variants,
  ...props
}: FlipTextProps) {
  const MotionComponent = motion(Component);
  const characters = React.Children.toArray(children).join("").split("");

  return (
    <div className="flex justify-center space-x-2">
      {characters.map((char, i) => (
        <MotionComponent
          key={i}
          initial="hidden"
          animate="visible"
          exit="hidden"
          variants={variants || defaultVariants}
          transition={{ duration, delay: i * delayMultiple }}
          className={cn("origin-center drop-shadow-sm", className)}
          {...props}
        >
          {char}
        </MotionComponent>
      ))}
    </div>
  );
}
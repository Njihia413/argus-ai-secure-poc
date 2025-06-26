"use client";

import createGlobe, { COBEOptions } from "cobe";
import { useMotionValue, useSpring } from "framer-motion";
import { useEffect, useRef } from "react";
import { useTheme } from "next-themes";
import { cn } from "@/lib/utils";

const MOVEMENT_DAMPING = 1400;

// Light theme config
const LIGHT_CONFIG: Partial<COBEOptions> = {
  dark: 0,
  baseColor: [1, 1, 1],
  glowColor: [1, 1, 1],
  markerColor: [0.93, 0.33, 0.11],
};

// Dark theme config
const DARK_CONFIG: Partial<COBEOptions> = {
  dark: 1,
  baseColor: [0.15, 0.15, 0.15],
  glowColor: [0.2, 0.2, 0.2],
  markerColor: [0.93, 0.33, 0.11],
};

const BASE_CONFIG: COBEOptions = {
  width: 1200,
  height: 1200,
  onRender: () => {},
  devicePixelRatio: 2,
  phi: 0,
  theta: 0.3,
  diffuse: 0.4,
  mapSamples: 8000,
  mapBrightness: 1.2,
  baseColor: [1, 1, 1],
  markerColor: [0.93, 0.33, 0.11],
  glowColor: [1, 1, 1],
  dark: 0,
  markers: [
    // Kenya markers with increased sizes
    { location: [-1.2921, 36.8219], size: 0.15 }, // Nairobi
  ],
};

export function Globe({
  className,
  config = {},
}: {
  className?: string;
  config?: Partial<COBEOptions>;
}) {
  const { resolvedTheme } = useTheme();
  let phi = 0;
  let width = 0;
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pointerInteracting = useRef<number | null>(null);
  const pointerInteractionMovement = useRef(0);

  const r = useMotionValue(0);
  const rs = useSpring(r, {
    mass: 1,
    damping: 20,
    stiffness: 80,
  });

  const updatePointerInteraction = (value: number | null) => {
    pointerInteracting.current = value;
    if (canvasRef.current) {
      canvasRef.current.style.cursor = value !== null ? "grabbing" : "grab";
    }
  };

  const updateMovement = (clientX: number) => {
    if (pointerInteracting.current !== null) {
      const delta = clientX - pointerInteracting.current;
      pointerInteractionMovement.current = delta;
      r.set(r.get() + delta / MOVEMENT_DAMPING);
    }
  };

  useEffect(() => {
    const onResize = () => {
      if (canvasRef.current) {
        width = canvasRef.current.offsetWidth;
      }
    };

    window.addEventListener("resize", onResize);
    onResize();

    const themeConfig = resolvedTheme === "dark" ? DARK_CONFIG : LIGHT_CONFIG;
    const globeConfig = {
      ...BASE_CONFIG,
      ...themeConfig,
      ...config,
      width: width * 2,
      height: width * 2,
      onRender: (state: Record<string, any>) => {
        if (!pointerInteracting.current) phi += 0.0025;
        state.phi = phi + rs.get();
        state.width = width * 2;
        state.height = width * 2;
      },
    };

    const globe = createGlobe(canvasRef.current!, globeConfig);

    setTimeout(() => (canvasRef.current!.style.opacity = "1"), 0);
    return () => {
      globe.destroy();
      window.removeEventListener("resize", onResize);
    };
  }, [rs, config, resolvedTheme]);

  return (
    <div
      className={cn(
        "absolute inset-0 mx-auto aspect-[1/1] w-full max-w-[1200px]",
        className
      )}
    >
      <canvas
        className={cn(
          "size-full opacity-0 transition-opacity duration-500 [contain:layout_paint_size]"
        )}
        ref={canvasRef}
        onPointerDown={(e) => {
          pointerInteracting.current = e.clientX;
          updatePointerInteraction(e.clientX);
        }}
        onPointerUp={() => updatePointerInteraction(null)}
        onPointerOut={() => updatePointerInteraction(null)}
        onMouseMove={(e) => updateMovement(e.clientX)}
        onTouchMove={(e) =>
          e.touches[0] && updateMovement(e.touches[0].clientX)
        }
      />
    </div>
  );
}
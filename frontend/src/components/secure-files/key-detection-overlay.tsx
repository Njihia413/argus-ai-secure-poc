"use client";

import { Shield, Smartphone, Loader2, CheckCircle2 } from "lucide-react";
import { YubiKey } from "@/app/hooks/use-yubikey-detection";

interface KeyDetectionOverlayProps {
  detectedKey: YubiKey | null;
  isConnected: boolean;
  isVerifying: boolean;
  title?: string;
  description?: string;
}

export function KeyDetectionOverlay({
  detectedKey,
  isConnected,
  isVerifying,
  title = "Security Key Detection",
  description = "Please plug in your security key to continue."
}: KeyDetectionOverlayProps) {
  return (
    <div className="p-6 border-2 border-dashed rounded-xl bg-muted/30 flex flex-col items-center justify-center text-center space-y-4 animate-in fade-in zoom-in duration-300">
      {!detectedKey ? (
        <>
          <div className="relative">
            <Smartphone className="h-12 w-12 text-muted-foreground animate-pulse" />
            <Shield className="h-6 w-6 text-primary absolute -bottom-1 -right-1" />
          </div>
          <div className="space-y-1">
            <h3 className="font-semibold text-lg font-montserrat">{title}</h3>
            <p className="text-sm text-muted-foreground font-montserrat">
              {isConnected ? description : "Connecting to detection service..."}
            </p>
          </div>
          {isVerifying && (
            <div className="flex items-center gap-2 text-xs text-primary animate-pulse">
              <Loader2 className="h-3 w-3 animate-spin" />
              Verifying hardware...
            </div>
          )}
        </>
      ) : (
        <>
          <div className="h-16 w-16 bg-primary/10 rounded-full flex items-center justify-center">
            <CheckCircle2 className="h-10 w-10 text-primary" />
          </div>
          <div className="space-y-1">
            <h3 className="font-semibold text-lg font-montserrat">Key Detected</h3>
            <div className="flex flex-col items-center justify-center p-3 bg-background border rounded-lg shadow-sm">
              <span className="text-sm font-bold text-primary font-montserrat">
                {detectedKey.device_type || "Security Key"}
              </span>
              <span className="text-xs text-muted-foreground font-mono">
                Serial: {detectedKey.serial}
              </span>
              <span className="text-[10px] mt-1 uppercase tracking-wider text-muted-foreground/70">
                Firmware: {detectedKey.version}
              </span>
            </div>
          </div>
          {detectedKey.id ? (
            <p className="text-xs text-green-600 font-medium font-montserrat">
              Verified & Matched to Account
            </p>
          ) : (
            <p className="text-xs text-amber-600 font-medium font-montserrat">
              Detected but not registered to you
            </p>
          )}
        </>
      )}
    </div>
  );
}

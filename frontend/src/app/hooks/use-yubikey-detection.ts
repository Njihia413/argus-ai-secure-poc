"use client";

import { useState, useEffect, useCallback } from "react";
import { io, Socket } from "socket.io-client";
import { API_URL } from "@/app/utils/constants";

export interface YubiKey {
  serial: number;
  version: string;
  form_factor: string;
  device_type: string;
  is_fips: boolean;
  is_sky: boolean;
  id?: number; // Database ID if verified
}

export function useYubiKeyDetection(isOpen: boolean) {
  const [detectedKeys, setDetectedKeys] = useState<YubiKey[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);

  const verifyKeyWithBackend = useCallback(async (key: YubiKey) => {
    try {
      const storedUser = sessionStorage.getItem("user");
      const token = storedUser ? JSON.parse(storedUser).authToken : null;

      const response = await fetch(`${API_URL}/security-keys/check-serial`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ serialNumber: key.serial }),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.exists) {
          return { ...key, id: data.id };
        }
      }
      return key;
    } catch (error) {
      console.error("Verification error:", error);
      return key;
    }
  }, []);

  useEffect(() => {
    if (!isOpen) {
      setDetectedKeys([]);
      return;
    }

    const socket: Socket = io("http://localhost:5000", {
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      transports: ["polling", "websocket"],
    });

    socket.on("connect", () => setIsConnected(true));
    socket.on("disconnect", () => setIsConnected(false));

    socket.on("yubikeys_update", async (data: { yubikeys: YubiKey[] }) => {
      setIsVerifying(true);
      const keysWithIds = await Promise.all(
        data.yubikeys.map((key) => verifyKeyWithBackend(key))
      );
      setDetectedKeys(keysWithIds);
      setIsVerifying(false);
    });

    // Initial fetch
    const fetchInitial = async () => {
      try {
        const storedUser = sessionStorage.getItem("user");
        const token = storedUser ? JSON.parse(storedUser).authToken : null;
        
        const response = await fetch(`${API_URL}/security-keys/detect-yubikeys`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.success) {
            setIsVerifying(true);
            const keysWithIds = await Promise.all(
              data.yubikeys.map((key: YubiKey) => verifyKeyWithBackend(key))
            );
            setDetectedKeys(keysWithIds);
            setIsVerifying(false);
          }
        }
      } catch (error) {
        console.error("Initial fetch error:", error);
      }
    };
    fetchInitial();

    return () => {
      socket.disconnect();
    };
  }, [isOpen, verifyKeyWithBackend]);

  return { detectedKeys, isConnected, isVerifying };
}

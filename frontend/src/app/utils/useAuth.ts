"use client";

import { useEffect, useState, useCallback } from "react";

export interface StoredUser {
  id: number;
  username: string;
  firstName: string;
  lastName: string;
  role: string;
  email?: string;
  hasSecurityKey?: boolean;
  securityKeyAuthenticated?: boolean;
  authToken?: string;
  hasElevatedAccess?: boolean;
}

const STORAGE_KEY = "user";
const CHANGE_EVENT = "argus-auth-change";

function readUser(): StoredUser | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as StoredUser) : null;
  } catch {
    return null;
  }
}

function writeUser(user: StoredUser | null) {
  if (typeof window === "undefined") return;
  if (user) {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(user));
  } else {
    sessionStorage.removeItem(STORAGE_KEY);
  }
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT));
}

/**
 * Single source of truth for auth state. Reads from sessionStorage and
 * re-renders on login/logout/key-flip via a custom event.
 */
export function useAuth() {
  const [user, setUser] = useState<StoredUser | null>(() => readUser());

  useEffect(() => {
    const sync = () => setUser(readUser());
    window.addEventListener(CHANGE_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(CHANGE_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const updateUser = useCallback((next: StoredUser | null | ((prev: StoredUser | null) => StoredUser | null)) => {
    const resolved = typeof next === "function" ? next(readUser()) : next;
    writeUser(resolved);
    setUser(resolved);
  }, []);

  const patchUser = useCallback((patch: Partial<StoredUser>) => {
    const current = readUser();
    if (!current) return;
    const merged = { ...current, ...patch };
    writeUser(merged);
    setUser(merged);
  }, []);

  const clearUser = useCallback(() => {
    writeUser(null);
    setUser(null);
  }, []);

  return {
    user,
    authToken: user?.authToken ?? null,
    role: user?.role ?? null,
    hasElevatedAccess: Boolean(user?.hasElevatedAccess),
    setUser: updateUser,
    patchUser,
    setHasElevatedAccess: (v: boolean) => patchUser({ hasElevatedAccess: v }),
    clearUser,
  };
}

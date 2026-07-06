import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

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

interface AuthState {
  user: StoredUser | null;
  _hasHydrated: boolean;
  setUser: (user: StoredUser | null) => void;
  patchUser: (patch: Partial<StoredUser>) => void;
  clearUser: () => void;
  setHasHydrated: (v: boolean) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      _hasHydrated: false,
      setUser: (user) => set({ user }),
      patchUser: (patch) => {
        const current = get().user;
        if (current) set({ user: { ...current, ...patch } });
      },
      clearUser: () => set({ user: null }),
      setHasHydrated: (v) => set({ _hasHydrated: v }),
    }),
    {
      name: "argus-auth",
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({ user: state.user }),
      onRehydrateStorage: () => (state, error) => {
        if (error) {
          // Rehydration failed (e.g. corrupted sessionStorage); unblock the UI
          useAuthStore.setState({ _hasHydrated: true });
        } else {
          state?.setHasHydrated(true);
        }
      },
    }
  )
);

export const getAuthUser = (): StoredUser | null => useAuthStore.getState().user;
export const getAuthToken = (): string | null =>
  useAuthStore.getState().user?.authToken ?? null;

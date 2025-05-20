import { create } from 'zustand';

export interface User {
  id: number;
  username: string;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
}

interface Store {
  authToken: string | null;
  setAuthToken: (token: string | null) => void;
  user: User | null;
  setUser: (user: User | null) => void;
}

export const useStore = create<Store>((set: any) => ({
  authToken: null,
  setAuthToken: (token: string | null) => set({ authToken: token }),
  user: null,
  setUser: (user: User | null) => set({ user }),
}));
"use client";

import { modelID } from "@/ai/providers";
import { useChat } from "@ai-sdk/react";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { toast } from 'sonner';
import { Textarea } from "@/components/textarea";
import { ProjectOverview } from "@/components/project-overview";
import { Messages } from "@/components/messages";
import { Header } from "@/components/header";
// Removed AvailableModels import from here, it's not needed for state typing
// Removed duplicate modelID import

// Type definitions
interface UserData {
  username: string;
  firstName: string;
  lastName: string;
  hasSecurityKey: boolean;
  role?: string; // Assuming role might be available
}

// Type for model dictionaries - make it a partial record to allow subsets of models
type ModelDict = Partial<Record<modelID, string>>;

// Define Model Lists
const ALL_MODELS = {
  "llama-3.1-8b-instant": "A fast cheap model",
  "deepseek-r1-distill-llama-70b": "A reasoning model",
  "llama-3.3-70b-versatile": "A large model",
};

const RESTRICTED_MODELS: ModelDict = {
  "llama-3.1-8b-instant": "Default Model",
};

const DEFAULT_MODEL_ID: modelID = "llama-3.1-8b-instant";

export default function Page() {
  const router = useRouter();
  const [userData, setUserData] = useState<UserData | null>(null);
  const [availableModels, setAvailableModels] = useState<ModelDict>(RESTRICTED_MODELS);
  const [selectedModel, setSelectedModel] = useState<modelID>(DEFAULT_MODEL_ID);

  const {
    messages,
    input,
    handleInputChange,
    handleSubmit,
    error,
    status,
    stop,
  } = useChat({
    maxSteps: 5,
    body: {
      selectedModel,
    },
  });

  const isLoading = status === "streaming" || status === "submitted";

  // Check authentication status on page load
  useEffect(() => {
    const checkAuth = async () => {
      try {
        // Get user data from session storage
        const storedUser = sessionStorage.getItem('user');
        const userData = storedUser ? JSON.parse(storedUser) : null;

        if (!userData || !userData.username) {
          // For demo purposes, create a mock user if none exists
          const mockUser: UserData = {
            username: 'demo@example.com',
            firstName: 'Demo',
            lastName: 'User',
            hasSecurityKey: false
          };
          sessionStorage.setItem('user', JSON.stringify(mockUser));
          setUserData(mockUser);
        } else {
          setUserData(userData as UserData);
        }
      } catch (err) {
        console.error('Error checking authentication:', err);
        // Create mock user instead of redirecting for demo purposes
        const mockUser: UserData = {
          username: 'demo@example.com',
          firstName: 'Demo',
          lastName: 'User',
          hasSecurityKey: false
        };
        sessionStorage.setItem('user', JSON.stringify(mockUser));
        setUserData(mockUser);
      }
    };

    checkAuth();
  }, []); // End of initial auth check useEffect
// Set initial models based on user's security key status
useEffect(() => {
  if (!userData?.hasSecurityKey) {
    setAvailableModels(RESTRICTED_MODELS);
    setSelectedModel(DEFAULT_MODEL_ID);
    return;
  }

  // Get initial state from localStorage or default to connected
  const storedKeyState = localStorage.getItem('securityKeyConnected');
  const initialKeyState = storedKeyState === null ? true : storedKeyState === 'true';
  
  // Set initial models based on stored state
  if (initialKeyState) {
    setAvailableModels(ALL_MODELS);
  } else {
    setAvailableModels(RESTRICTED_MODELS);
    setSelectedModel(DEFAULT_MODEL_ID);
  }

  // Function to update state based on key status
  const updateKeyState = (isConnected: boolean) => {
    localStorage.setItem('securityKeyConnected', String(isConnected));
    
    if (isConnected) {
      setAvailableModels(ALL_MODELS);
      toast.success("Security key connected. Full model access restored.");
    } else {
      setAvailableModels(RESTRICTED_MODELS);
      setSelectedModel(DEFAULT_MODEL_ID);
      toast.error("Security key disconnected. Access restricted to default model.");
    }
  };

  // Handle keypress to simulate key removal/insertion (Alt + K)
  const handleKeyPress = (event: KeyboardEvent) => {
    if (event.altKey && event.key === 'k') {
      const newKeyState = !JSON.parse(localStorage.getItem('securityKeyConnected') || 'true');
      updateKeyState(newKeyState);
    }
  };

  // Handle storage changes from other tabs
  const handleStorageChange = (e: StorageEvent) => {
    if (e.key === 'securityKeyConnected') {
      const newState = e.newValue === 'true';
      setAvailableModels(newState ? ALL_MODELS : RESTRICTED_MODELS);
      if (!newState) {
        setSelectedModel(DEFAULT_MODEL_ID);
        toast.error("Security key disconnected in another tab. Access restricted to default model.");
      }
    }
  };

  // Add event listeners
  window.addEventListener('keydown', handleKeyPress);
  window.addEventListener('storage', handleStorageChange);

  // Clear key state on page unload
  window.addEventListener('beforeunload', () => {
    localStorage.removeItem('securityKeyConnected');
  });

  // Clean up
  return () => {
    window.removeEventListener('keydown', handleKeyPress);
    window.removeEventListener('storage', handleStorageChange);
  };
}, [userData]);



  if (error) return <div>{error.message}</div>;

  // Loading state while checking initial auth/user data
  if (!userData) {
    return (
        <div className="flex items-center justify-center min-h-screen">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary"></div>
        </div>
    );
  }

  // Main chat UI
  return (
      <div className="h-dvh flex flex-col justify-center font-montserrat w-full stretch">
        <Header />

        {messages.length === 0 ? (
            <div className="max-w-xl mx-auto w-full">
              <ProjectOverview />
            </div>
        ) : (
            <Messages messages={messages} isLoading={isLoading} status={status} />
        )}

        <form
            onSubmit={handleSubmit}
            className="pb-8 bg-white dark:bg-black w-full max-w-xl mx-auto px-4 sm:px-0"
        >
          {/* Pass availableModels down */}
          <Textarea
              selectedModel={selectedModel}
              setSelectedModel={setSelectedModel}
              handleInputChange={handleInputChange}
              input={input}
              isLoading={isLoading}
              status={status}
              stop={stop}
              models={availableModels} // Pass the dynamic models list
          />
        </form>
      </div>
  );
}


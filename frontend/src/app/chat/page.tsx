"use client";

import { modelID } from "@/ai/providers";
import { useChat } from "@ai-sdk/react";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { toast } from 'sonner';
import { Textarea } from "@/components/textarea";
import { ProjectOverview } from "@/components/project-overview";
import { Messages } from "@/components/messages";
import { Header } from "@/components/header";
import {
  checkSecurityKeyStatus,
  requestSecurityKeyAccess,
  isWebUSBSupported
} from "@/app/utils/webauthn";

// Type definitions
interface UserData {
  id: string;
  username: string;
  firstName: string;
  lastName: string;
  hasSecurityKey: boolean;
  securityKeyAuthenticated?: boolean;
  role?: string;
  authToken?: string;
}

// Type for model dictionaries - make it a partial record to allow subsets of models
type ModelDict = Partial<Record<modelID, string>>;

// Define Model Lists - Use model IDs as the display names
const ALL_MODELS = {
  "llama-3.1-8b-instant": "llama-3.1-8b-instant",
  "deepseek-r1-distill-llama-70b": "deepseek-r1-distill-llama-70b",
  "llama-3.3-70b-versatile": "llama-3.3-70b-versatile",
};

const RESTRICTED_MODELS: ModelDict = {
  "llama-3.1-8b-instant": "llama-3.1-8b-instant",
};

const DEFAULT_MODEL_ID: modelID = "llama-3.1-8b-instant";

// How frequently to check security key status (in milliseconds)
const KEY_CHECK_INTERVAL = 3000; // Every 3 seconds

export default function ChatPage() {
  const router = useRouter();
  const [userData, setUserData] = useState<UserData | null>(null);
  const [availableModels, setAvailableModels] = useState<ModelDict>(RESTRICTED_MODELS);
  const [selectedModel, setSelectedModel] = useState<modelID>(DEFAULT_MODEL_ID);
  const [securityKeyStatus, setSecurityKeyStatus] = useState<boolean>(false);
  const securityKeyDetectionInterval = useRef<NodeJS.Timeout | null>(null);
  const keyCheckInProgress = useRef<boolean>(false);
  const initialLoadComplete = useRef<boolean>(false);
  const webUSBSupported = useRef<boolean>(false);

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

  // Check WebUSB support on initial load
  useEffect(() => {
    webUSBSupported.current = isWebUSBSupported();
    console.log("WebUSB supported:", webUSBSupported.current);
  }, []);

  // Check authentication status on page load
  useEffect(() => {
    const checkAuth = async () => {
      try {
        // Get user data from session storage
        const storedUser = sessionStorage.getItem('user');
        const userData = storedUser ? JSON.parse(storedUser) : null;

        if (!userData || !userData.username) {
          // Redirect to login page if not authenticated
          router.push("/login");
          return;
        }

        setUserData(userData as UserData);

        // Check if the user logged in with a security key
        const isSecurityKeyAuth = userData.securityKeyAuthenticated === true;

        // Set initial security key status based on auth method
        setSecurityKeyStatus(isSecurityKeyAuth);

        // Set initial models based on auth method
        if (isSecurityKeyAuth) {
          setAvailableModels(ALL_MODELS);
          // Only show toast on initial page load
          if (!initialLoadComplete.current) {
            toast.success("Security Key: Connected - Full model access");
            initialLoadComplete.current = true;
          }
        } else {
          setAvailableModels(RESTRICTED_MODELS);
          setSelectedModel(DEFAULT_MODEL_ID);
        }
      } catch (err) {
        console.error('Error checking authentication:', err);
        toast.error('Session error. Please login again.');
        router.push("/login");
      }
    };

    checkAuth();
  }, [router]);

  // Force update selected model when available models change
  useEffect(() => {
    // If the currently selected model isn't available in RESTRICTED_MODELS
    // and the security key is disconnected, reset to default model
    if (!RESTRICTED_MODELS[selectedModel] && !securityKeyStatus) {
      console.log("Forcing model reset to default because current selection is unavailable");
      setSelectedModel(DEFAULT_MODEL_ID);
    }
  }, [availableModels, selectedModel, securityKeyStatus]);

  // Monitor security key connection status
  useEffect(() => {
    if (!userData?.hasSecurityKey || !userData?.securityKeyAuthenticated) {
      return; // Don't monitor if user doesn't have a security key or didn't authenticate with one
    }

    console.log("Setting up security key monitoring");

    // Helper function to check key status
    const checkKeyStatus = async () => {
      // Prevent multiple simultaneous checks
      if (keyCheckInProgress.current) return;

      keyCheckInProgress.current = true;

      try {
        const isConnected = await checkSecurityKeyStatus(userData.username);
        console.log("Security key status check result:", isConnected, "Current state:", securityKeyStatus);

        // Only update state if the status has changed
        if (isConnected !== securityKeyStatus) {
          console.log("Security key status changed from", securityKeyStatus, "to", isConnected);

          // Update status first
          setSecurityKeyStatus(isConnected);

          if (!isConnected) {
            // When disconnected, restrict models and reset selection
            toast.error("Security key disconnected. Access restricted to default model.");
            setAvailableModels(RESTRICTED_MODELS);
            setSelectedModel(DEFAULT_MODEL_ID);
          } else {
            // When connected, expand available models
            toast.success("Security key connected. Full model access restored.");
            setAvailableModels(ALL_MODELS);
          }
        }
      } catch (error) {
        console.error('Error checking security key status:', error);
      } finally {
        keyCheckInProgress.current = false;
      }
    };

    // Run initial check
    checkKeyStatus();

    // Set up interval for periodic checking
    securityKeyDetectionInterval.current = setInterval(checkKeyStatus, KEY_CHECK_INTERVAL);

    // Add keyboard shortcut for simulating key removal/insertion (Alt + K)
    // This is for development/demo purposes only
    const handleKeyPress = (event: KeyboardEvent) => {
      if (event.altKey && event.key === 'k') {
        const newKeyState = !securityKeyStatus;
        console.log("Simulating security key state change:", newKeyState);

        setSecurityKeyStatus(newKeyState);

        if (!newKeyState) {
          // Force immediate model restriction
          console.log("Restricting models to:", Object.keys(RESTRICTED_MODELS));
          setAvailableModels(RESTRICTED_MODELS);
          setSelectedModel(DEFAULT_MODEL_ID);
          toast.error("Security key disconnected. Access restricted to default model.");
        } else {
          console.log("Expanding models to:", Object.keys(ALL_MODELS));
          setAvailableModels(ALL_MODELS);
          toast.success("Security key connected. Full model access restored.");
        }

        // Update localStorage for simulation
        localStorage.setItem('securityKeyConnected', newKeyState ? 'true' : 'false');
      }
    };

    window.addEventListener('keydown', handleKeyPress);

    // Handle storage changes from other tabs
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'securityKeyConnected') {
        const newState = e.newValue === 'true';
        console.log("Security key status changed in another tab:", newState);

        if (newState !== securityKeyStatus) {
          setSecurityKeyStatus(newState);

          if (!newState) {
            // Force immediate model restriction
            setAvailableModels(RESTRICTED_MODELS);
            setSelectedModel(DEFAULT_MODEL_ID);
            toast.error("Security key disconnected in another tab. Access restricted.");
          } else {
            setAvailableModels(ALL_MODELS);
            toast.success("Security key connected. Full model access restored.");
          }
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);

    // Cleanup
    return () => {
      if (securityKeyDetectionInterval.current) {
        clearInterval(securityKeyDetectionInterval.current);
      }
      window.removeEventListener('keydown', handleKeyPress);
      window.removeEventListener('storage', handleStorageChange);
    };
  }, [userData, securityKeyStatus]);

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
          {/* Pass availableModels down to Textarea component */}
          <Textarea
              selectedModel={selectedModel}
              setSelectedModel={setSelectedModel}
              handleInputChange={handleInputChange}
              input={input}
              isLoading={isLoading}
              status={status}
              stop={stop}
              models={availableModels}
          />
        </form>
      </div>
  );
}
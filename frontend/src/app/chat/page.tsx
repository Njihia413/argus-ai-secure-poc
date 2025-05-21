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
  const [isNormalUsbConnected, setIsNormalUsbConnected] = useState<boolean>(false);
  const [isHelperAppConnected, setIsHelperAppConnected] = useState<boolean>(false);
  const wsRef = useRef<WebSocket | null>(null);
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

        // Initial model setting will be handled by the combined useEffect.
        // We still set initialLoadComplete here.
        if (isSecurityKeyAuth && !initialLoadComplete.current) {
            // toast.success("Logged in with Security Key."); // Toast handled by combined logic
        }
        if (!initialLoadComplete.current) {
            initialLoadComplete.current = true;
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
    if (Object.keys(availableModels).length > 0 && !availableModels[selectedModel]) {
        console.log(`Selected model ${selectedModel} not in newly set available models (${Object.keys(availableModels).join(', ')}). Resetting.`);
        if (availableModels[DEFAULT_MODEL_ID]) {
            setSelectedModel(DEFAULT_MODEL_ID);
        } else if (Object.keys(availableModels).length > 0) { // Ensure there's at least one model
            setSelectedModel(Object.keys(availableModels)[0] as modelID);
        }
    }
  }, [availableModels, selectedModel]);

  // WebSocket connection to Python helper for Normal USB detection
  useEffect(() => {
    console.log("WebSocket useEffect triggered. UserData:", userData ? "Exists" : "null", "wsRef.current:", wsRef.current ? wsRef.current.readyState : "null"); // DEBUG LOG

    if (!userData) {
      if (wsRef.current) {
        console.log("No user data, ensuring old WebSocket is closed.");
        wsRef.current.close();
      }
      return;
    }

    if (wsRef.current && wsRef.current.readyState < WebSocket.CLOSING) {
      console.log("WebSocket connection attempt skipped: already exists or connecting.");
      return;
    }
    
    console.log("Attempting to connect to Normal USB helper WebSocket...");
    const socket = new WebSocket("ws://localhost:12345");
    wsRef.current = socket;

    let initialConnectionFailed = true;

    socket.onopen = () => {
      initialConnectionFailed = false;
      console.log("Connected to Normal USB helper WebSocket.");
      setIsHelperAppConnected(true);
      toast.success("USB Helper: Connected");
    };

    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data as string);
        console.log("Message from Normal USB helper:", message);
        if (message.event === "NORMAL_USB_CONNECTED") {
          console.log("setIsNormalUsbConnected called with true");
          setIsNormalUsbConnected(true);
        } else if (message.event === "NORMAL_USB_DISCONNECTED") {
          console.log("setIsNormalUsbConnected called with false");
          setIsNormalUsbConnected(false);
        }
      } catch (error) {
        console.error("Failed to parse message from Normal USB helper:", error);
      }
    };

    socket.onerror = (error) => {
      console.error("Normal USB helper WebSocket error:", error);
      if (initialConnectionFailed && wsRef.current === socket) {
          toast.error("USB Helper: Failed to connect.");
      } else if (isHelperAppConnected) {
          toast.error("USB Helper: Connection error.");
      }
    };

    socket.onclose = () => {
      console.log("Disconnected from Normal USB helper WebSocket.");
      if (isHelperAppConnected && !initialConnectionFailed) {
         toast.info("USB Helper: Disconnected.");
      }
      
      setIsHelperAppConnected(false);
      setIsNormalUsbConnected(false);
      
      if (wsRef.current === socket) {
        wsRef.current = null;
      }
    };

    return () => {
      console.log("Cleaning up WebSocket effect for Normal USB helper.");
      if (socket) {
        console.log(`Closing WebSocket (readyState: ${socket.readyState}) in cleanup.`);
        socket.onopen = null;
        socket.onmessage = null;
        socket.onerror = null;
        socket.onclose = null;
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
          socket.close();
        }
      }
      if (wsRef.current === socket) {
          wsRef.current = null;
      }
    };
  }, [userData]);

  // Combined logic for setting availableModels
  useEffect(() => {
    if (!userData) {
      if (JSON.stringify(availableModels) !== JSON.stringify(RESTRICTED_MODELS)) {
        setAvailableModels(RESTRICTED_MODELS);
      }
      return;
    }

    const loggedInWithSecurityKeyAtAuthTime = userData.securityKeyAuthenticated === true;
    let newAvailableModels = RESTRICTED_MODELS;
    let toastMessage: { type: 'success' | 'error' | 'info'; message: string } | null = null;

    console.log(
      "Combined logic check:",
      { loggedInWithSecurityKeyAtAuthTime },
      { securityKeyStatus },
      { isNormalUsbConnected },
      { isHelperAppConnected },
      { currentAvailableModels: JSON.stringify(availableModels) }
    );

    if (loggedInWithSecurityKeyAtAuthTime) {
      if (securityKeyStatus) {
        newAvailableModels = ALL_MODELS;
      } else {
        newAvailableModels = RESTRICTED_MODELS;
      }
    } else {
      if (isNormalUsbConnected && isHelperAppConnected) {
        newAvailableModels = ALL_MODELS;
        if (JSON.stringify(availableModels) !== JSON.stringify(ALL_MODELS)) {
            toastMessage = { type: 'success', message: "Normal USB Detected: Full model access enabled." };
        }
      } else {
        newAvailableModels = RESTRICTED_MODELS;
        if (JSON.stringify(availableModels) !== JSON.stringify(RESTRICTED_MODELS)) {
            if (isHelperAppConnected && initialLoadComplete.current && !isNormalUsbConnected) { // Check initialLoadComplete
                toastMessage = { type: 'error', message: "Normal USB Disconnected/Not Found: Model access restricted." };
            }
        }
      }
    }
    
    if (JSON.stringify(availableModels) !== JSON.stringify(newAvailableModels)) {
        console.log("Setting new available models:", newAvailableModels);
        setAvailableModels(newAvailableModels);
        if (toastMessage) {
            toast[toastMessage.type](toastMessage.message);
        }
    } else {
      if (toastMessage && JSON.stringify(availableModels) === JSON.stringify(newAvailableModels)) {
           console.log("Models unchanged, but showing toast:", toastMessage.message);
           toast[toastMessage.type](toastMessage.message);
      } else {
           console.log("Available models did not change, no toast needed.", availableModels);
      }
    }

  }, [userData, securityKeyStatus, isNormalUsbConnected, isHelperAppConnected, availableModels, initialLoadComplete]); // Added initialLoadComplete


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
          
          setSecurityKeyStatus(isConnected);
 
          if (!isConnected) {
            toast.error("Security Key: Disconnected. Model access may be restricted.");
          } else {
            toast.success("Security Key: Connected. Full model access may be restored.");
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
          toast.error("Simulated: Security key disconnected. Model access may be restricted.");
        } else {
          toast.success("Simulated: Security key connected. Full model access may be restored.");
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
            toast.error("Security key status changed in another tab: Disconnected. Model access may be restricted.");
          } else {
            toast.success("Security key status changed in another tab: Connected. Full model access may be restored.");
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
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
  const [isSecurityKeyHidConnected, setIsSecurityKeyHidConnected] = useState<boolean>(false);
  const [connectedSecurityKeyHidDetails, setConnectedSecurityKeyHidDetails] = useState<{vendorId: number, productId: number, path: string} | null>(null);
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

  // WebSocket connection to Python helper for USB detection
  useEffect(() => {
    if (!userData) {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null; // Ensure it's cleared
      }
      return;
    }

    let connectTimeoutId: NodeJS.Timeout | null = null;
    let retryCount = 0;
    const maxRetries = 5;
    const retryDelay = 3000; // 3 seconds

    function connectWebSocket() {
      // If already connected or connecting, don't try again
      if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
        console.log("WebSocket connection attempt skipped: already open or connecting.");
        return;
      }

      console.log(`Attempting to connect to USB helper WebSocket (Attempt: ${retryCount + 1})...`);
      const socket = new WebSocket("ws://localhost:12345");
      wsRef.current = socket; // Assign immediately

      let hasConnectedSuccessfully = false; // Track if onopen was ever called for this attempt

      socket.onopen = () => {
        hasConnectedSuccessfully = true;
        retryCount = 0; // Reset retry count on successful connection
        if (connectTimeoutId) clearTimeout(connectTimeoutId); // Clear any pending retry timeout
        console.log("Connected to USB helper WebSocket.");
        setIsHelperAppConnected(true);
        toast.success("USB Helper: Connected");
      };

      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data as string);
          console.log("Message from USB helper:", message); // General log

          switch (message.event) {
            case "NORMAL_USB_CONNECTED":
              console.log("FRONTEND: Processing NORMAL_USB_CONNECTED");
              setIsNormalUsbConnected(true);
              break;
            case "NORMAL_USB_DISCONNECTED":
              console.log("FRONTEND: Processing NORMAL_USB_DISCONNECTED");
              setIsNormalUsbConnected(false);
              break;
            case "SECURITY_KEY_HID_CONNECTED":
              console.log("FRONTEND: Processing SECURITY_KEY_HID_CONNECTED event:", message);
              setIsSecurityKeyHidConnected(true);
              setConnectedSecurityKeyHidDetails({
                vendorId: message.vendorId,
                productId: message.productId,
                path: message.path
              });
              toast.success(`Security Key (HID) Connected: VID=${message.vendorId.toString(16)}, PID=${message.productId.toString(16)}`);
              break;
            case "SECURITY_KEY_HID_DISCONNECTED":
              console.log("FRONTEND: Processing SECURITY_KEY_HID_DISCONNECTED event:", message);
              // Check if the disconnected key is the one we are tracking
              if (connectedSecurityKeyHidDetails && connectedSecurityKeyHidDetails.path === message.path) {
                setIsSecurityKeyHidConnected(false);
                setConnectedSecurityKeyHidDetails(null);
                toast.error(`Tracked Security Key (HID) Disconnected: VID=${message.vendorId?.toString(16)}, PID=${message.productId?.toString(16)}`);
              } else if (isSecurityKeyHidConnected && !connectedSecurityKeyHidDetails && message.path) {
                // If we thought a HID key was connected but didn't have specific details,
                // and now a specific key disconnects, update our state.
                setIsSecurityKeyHidConnected(false);
                // No specific details to clear if connectedSecurityKeyHidDetails was already null
                toast.error(`A Security Key (HID) Disconnected: VID=${message.vendorId?.toString(16)}, PID=${message.productId?.toString(16)} (Path: ${message.path})`);
              } else if (isSecurityKeyHidConnected && !message.path) {
                // Generic disconnect if path isn't provided by older detector or some other scenario
                setIsSecurityKeyHidConnected(false);
                setConnectedSecurityKeyHidDetails(null);
                toast.error("A Security Key (HID) was disconnected (generic).");
              }
              break;
            default:
              console.warn("Received unknown message event from USB helper:", message);
          }
        } catch (error) {
          console.error("Failed to parse message from USB helper:", error);
        }
      };

      socket.onerror = (error) => {
        console.error("USB helper WebSocket error:", error);
        // Don't show "failed to connect" if onopen was called, as it might be a subsequent error
        if (!hasConnectedSuccessfully) {
            // toast.error("USB Helper: Connection error."); // This might be too noisy if it retries
        }
      };

      socket.onclose = (event) => {
        console.log(`Disconnected from USB helper WebSocket. Code: ${event.code}, Reason: ${event.reason}, Clean: ${event.wasClean}`);
        if (isHelperAppConnected && hasConnectedSuccessfully) { // Only show disconnected if it was previously connected
           toast.info("USB Helper: Disconnected.");
        }
        
        setIsHelperAppConnected(false);
        setIsNormalUsbConnected(false);
        setIsSecurityKeyHidConnected(false);
        setConnectedSecurityKeyHidDetails(null);
        
        if (wsRef.current === socket) { // Ensure we are clearing the correct ref
          wsRef.current = null;
        }

        // Attempt to reconnect if not a clean close and user is still on page
        if (userData && retryCount < maxRetries) {
          retryCount++;
          console.log(`Will attempt to reconnect in ${retryDelay / 1000}s (Attempt: ${retryCount}).`);
          if (connectTimeoutId) clearTimeout(connectTimeoutId); // Clear previous timeout
          connectTimeoutId = setTimeout(connectWebSocket, retryDelay);
        } else if (retryCount >= maxRetries) {
            console.log("Max WebSocket reconnection retries reached.");
            toast.error("USB Helper: Max reconnection attempts failed. Please ensure the helper app is running and refresh the page.");
        }
      };
    }

    connectWebSocket(); // Initial connection attempt

    return () => {
      console.log("Cleaning up WebSocket effect for USB helper.");
      if (connectTimeoutId) clearTimeout(connectTimeoutId);
      if (wsRef.current) {
        console.log(`Closing WebSocket (readyState: ${wsRef.current.readyState}) in cleanup.`);
        wsRef.current.onopen = null;
        wsRef.current.onmessage = null;
        wsRef.current.onerror = null;
        wsRef.current.onclose = null; // Important to prevent onclose from triggering retries after component unmount
        if (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING) {
          wsRef.current.close(1000, "Component unmounting"); // Clean close
        }
        wsRef.current = null;
      }
      // Reset states on cleanup
      setIsHelperAppConnected(false);
      setIsNormalUsbConnected(false);
      setIsSecurityKeyHidConnected(false);
      setConnectedSecurityKeyHidDetails(null);
    };
  }, [userData]); // Rerun if userData changes (e.g., on login/logout)

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
    let reasonForChange = "Default: Restricted models.";

    console.log(
      "Model Availability Check:",
      { loggedInWithSecurityKeyAtAuthTime },
      { securityKeyStatus }, // Browser API status
      { isNormalUsbConnected },
      { isSecurityKeyHidConnected }, // Physical HID status
      { isHelperAppConnected },
      { currentModels: Object.keys(availableModels) }
    );

    if (loggedInWithSecurityKeyAtAuthTime) {
      // User authenticated with a security key
      if (isSecurityKeyHidConnected) { // Check physical HID connection
        newAvailableModels = ALL_MODELS;
        reasonForChange = "Logged in with WebAuthn & Security Key (HID) is connected.";
      } else {
        newAvailableModels = RESTRICTED_MODELS;
        reasonForChange = "Logged in with WebAuthn, but Security Key (HID) is NOT connected.";
      }
    } else {
      // User authenticated with email/password
      if (isSecurityKeyHidConnected && isHelperAppConnected) {
        newAvailableModels = ALL_MODELS;
        reasonForChange = "Security Key (HID) connected (email/password login).";
      } else if (isNormalUsbConnected && isHelperAppConnected) {
        newAvailableModels = ALL_MODELS;
        reasonForChange = "Normal USB connected (email/password login).";
      } else {
        newAvailableModels = RESTRICTED_MODELS;
        if (!isHelperAppConnected && initialLoadComplete.current) {
            reasonForChange = "USB Helper not connected. Model access restricted.";
        } else if (isHelperAppConnected && !isNormalUsbConnected && !isSecurityKeyHidConnected && initialLoadComplete.current) {
            reasonForChange = "No recognized USB device connected. Model access restricted.";
        } else {
            reasonForChange = "Default for email/password login without recognized USB device.";
        }
      }
    }
    
    if (JSON.stringify(availableModels) !== JSON.stringify(newAvailableModels)) {
        console.log(`Setting new available models due to: ${reasonForChange}. New models: ${Object.keys(newAvailableModels).join(', ')}`);
        setAvailableModels(newAvailableModels);
        // Determine toast message based on the change
        if (JSON.stringify(newAvailableModels) === JSON.stringify(ALL_MODELS) && JSON.stringify(availableModels) !== JSON.stringify(ALL_MODELS)) {
            toast.success("Full model access enabled. " + reasonForChange);
        } else if (JSON.stringify(newAvailableModels) === JSON.stringify(RESTRICTED_MODELS) && JSON.stringify(availableModels) !== JSON.stringify(RESTRICTED_MODELS)) {
            toast.error("Model access restricted. " + reasonForChange);
        }
    } else {
         console.log(`Available models did not change (${Object.keys(availableModels).join(', ')}). Reason: ${reasonForChange}`);
    }

  }, [userData, securityKeyStatus, isNormalUsbConnected, isSecurityKeyHidConnected, isHelperAppConnected, availableModels, initialLoadComplete]);


  // Monitor security key connection status (WebAuthn browser API based)
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
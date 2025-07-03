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

type ModelDict = Partial<Record<modelID, string>>;

const ALL_MODELS = {
  "llama-3.1-8b-instant": "llama-3.1-8b-instant",
  "deepseek-r1-distill-llama-70b": "deepseek-r1-distill-llama-70b",
  "llama-3.3-70b-versatile": "llama-3.3-70b-versatile",
};

const RESTRICTED_MODELS: ModelDict = {
  "llama-3.1-8b-instant": "llama-3.1-8b-instant",
};

const DEFAULT_MODEL_ID: modelID = "llama-3.1-8b-instant";
const KEY_CHECK_INTERVAL = 3000;

interface HidKeyInfo {
  isConnected: boolean;
  path: string | null;
  vendorId: string | null;
  productId: string | null;
}

const initialHidKeyInfo: HidKeyInfo = {
  isConnected: false,
  path: null,
  vendorId: null,
  productId: null,
};

export default function ChatPage() {
  const router = useRouter();
  const [userData, setUserData] = useState<UserData | null>(null);
  const [availableModels, setAvailableModels] = useState<ModelDict>(RESTRICTED_MODELS);
  const [selectedModel, setSelectedModel] = useState<modelID>(DEFAULT_MODEL_ID);
  const [securityKeyStatus, setSecurityKeyStatus] = useState<boolean>(false); 

  const [isNormalUsbConnected, setIsNormalUsbConnected] = useState<boolean>(false);
  const [hidKey, setHidKey] = useState<HidKeyInfo>(initialHidKeyInfo);
  const hidKeyRef = useRef(hidKey); 
  useEffect(() => {
    hidKeyRef.current = hidKey;
    console.log("STATE TRACE: hidKey changed to:", hidKey, "and hidKeyRef updated."); 
  }, [hidKey]);

  const [isHelperAppConnected, setIsHelperAppConnected] = useState<boolean>(false);
  const wsRef = useRef<WebSocket | null>(null);
  const securityKeyDetectionInterval = useRef<NodeJS.Timeout | null>(null);
  const keyCheckInProgress = useRef<boolean>(false);
  const initialLoadComplete = useRef<boolean>(false);
  const webUSBSupported = useRef<boolean>(false);
  const hasLoggedWebSocketErrorRef = useRef<boolean>(false);

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
    body: { selectedModel },
  });

  const isLoading = status === "streaming" || status === "submitted";

  useEffect(() => {
    webUSBSupported.current = isWebUSBSupported();
    console.log("WebUSB supported:", webUSBSupported.current);
  }, []);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const storedUser = sessionStorage.getItem('user');
        const sessionUserData = storedUser ? JSON.parse(storedUser) : null;
        if (!sessionUserData || !sessionUserData.username) {
          router.push("/home");
          return;
        }
        setUserData(sessionUserData as UserData);
        const isSecurityKeyAuth = sessionUserData.securityKeyAuthenticated === true;
        setSecurityKeyStatus(isSecurityKeyAuth);
        if (!initialLoadComplete.current) {
            initialLoadComplete.current = true;
        }
      } catch (err) {
        console.error('Error checking authentication:', err);
        toast.error('Session error. Please login again.');
        router.push("/home");
      }
    };
    checkAuth();
  }, [router]);

  useEffect(() => {
    if (Object.keys(availableModels).length > 0 && !availableModels[selectedModel]) {
        console.log(`Selected model ${selectedModel} not in newly set available models. Resetting.`);
        if (availableModels[DEFAULT_MODEL_ID]) {
            setSelectedModel(DEFAULT_MODEL_ID);
        } else if (Object.keys(availableModels).length > 0) {
            setSelectedModel(Object.keys(availableModels)[0] as modelID);
        }
    }
  }, [availableModels, selectedModel]);

  useEffect(() => {
    if (!userData) {
      if (wsRef.current) {
        wsRef.current.close(1000, "User data cleared, closing WebSocket");
        wsRef.current = null;
      }
      return;
    }

    let connectTimeoutId: NodeJS.Timeout | null = null;
    const retryDelay = 3000;

    function connectWebSocket() {
      if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
        console.log("WebSocket connection attempt skipped: already open or connecting.");
        return;
      }
      console.log(`Attempting to connect to USB helper WebSocket...`);
      const socket = new WebSocket("ws://localhost:12345");
      wsRef.current = socket;
      let hasConnectedSuccessfully = false;

      socket.onopen = () => {
        // Removed: hasLoggedWebSocketErrorRef.current = false;
        // Now, the error will only be logged once per component lifecycle if it occurs.
        hasConnectedSuccessfully = true;
        if (connectTimeoutId) clearTimeout(connectTimeoutId);
        console.log("Connected to USB helper WebSocket.");
        setIsHelperAppConnected(true);
        toast.success("USB Helper: Connected");
      };

      socket.onmessage = (event) => {
        console.log("onmessage - State BEFORE processing (from ref): hidKeyRef.current:", hidKeyRef.current );
        try {
          const message = JSON.parse(event.data as string);
          console.log("Message from USB helper:", message);

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
              setHidKey({
                isConnected: true,
                path: message.path,
                vendorId: message.vendorId,
                productId: message.productId
              });
              toast.success(`Security Key (HID) Connected: VID=${message.vendorId}, PID=${message.productId}`);
              break;
            case "SECURITY_KEY_HID_DISCONNECTED":
              console.log("FRONTEND: Processing SECURITY_KEY_HID_DISCONNECTED event:", message);
              console.log("Disconnect Handler - State at entry (from ref): hidKeyRef.current.isConnected:", hidKeyRef.current.isConnected, "hidKeyRef.current.path:", hidKeyRef.current.path);
              console.log("Disconnect Handler - Message path:", message.path);

              if (hidKeyRef.current.path && hidKeyRef.current.path === message.path) {
                console.log("Disconnect Case 1: Tracked key matches disconnected path.");
                setHidKey(initialHidKeyInfo); 
                toast.error(`Security Key (HID) Disconnected: VID=${hidKeyRef.current.vendorId || 'N/A'}, PID=${hidKeyRef.current.productId || 'N/A'}`);
              } else if (hidKeyRef.current.isConnected && message.path && (!hidKeyRef.current.path || hidKeyRef.current.path !== message.path)) {
                console.log("Disconnect Case 2: A HID key disconnected, and we thought one was connected (path mismatch or no specific stored path).");
                setHidKey(initialHidKeyInfo);
                toast.error(`A Security Key (HID) Disconnected: VID=${message.vendorId || 'N/A'}, PID=${message.productId || 'N/A'} (Path: ${message.path || 'N/A'})`);
              } else if (hidKeyRef.current.isConnected && !message.path) {
                console.log("Disconnect Case 3: Generic HID disconnect (no path in message), and we thought one was connected.");
                setHidKey(initialHidKeyInfo);
                toast.error("Security Key (HID) Disconnected (Generic)"); // Updated
              } else {
                console.log("Disconnect Case 4: No conditions met to update state for HID disconnect.");
                if (!hidKeyRef.current.isConnected) {
                    console.log("Reason: hidKeyRef.current.isConnected is already false (at disconnect handler entry).");
                }
                if (hidKeyRef.current.path && hidKeyRef.current.path !== message.path) {
                    console.log(`Reason: Path mismatch. Stored (ref): '${hidKeyRef.current.path}', Received: '${message.path}' (at disconnect handler entry).`);
                }
                 if (!hidKeyRef.current.path && message.path) {
                    console.log("Reason: hidKeyRef.current.path is null, but message has a path (at disconnect handler entry).");
                }
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
        if (!hasLoggedWebSocketErrorRef.current) {
          console.warn("USB helper WebSocket warning (error downgraded to prevent overlay):", error);
          hasLoggedWebSocketErrorRef.current = true;
        }
      };

      socket.onclose = (event) => {
        console.log(`Disconnected from USB helper WebSocket. Code: ${event.code}, Reason: '${event.reason}', Clean: ${event.wasClean}`);
        if (isHelperAppConnected && hasConnectedSuccessfully) {
           toast.info("USB Helper: Disconnected.");
        }
        setIsHelperAppConnected(false);
        setIsNormalUsbConnected(false); 
        if (!event.wasClean) {
            console.warn("WebSocket closed uncleanly. HID key state might be stale if detector crashed.");
        }
        if (wsRef.current === socket) {
          wsRef.current = null;
        }
        if (userData && event.code !== 1000) { // If not a clean, intentional close by the server or client
            // Always attempt to reconnect if the closure was not intentional and user is logged in.
            // The hasLoggedWebSocketErrorRef is primarily to prevent the initial error overlay/toast spam,
            // but we still want to keep trying to connect in the background.
            console.log(`WebSocket closed unexpectedly. Will attempt to reconnect in ${retryDelay / 1000}s. Error logged previously: ${hasLoggedWebSocketErrorRef.current}`);
            if (connectTimeoutId) clearTimeout(connectTimeoutId);
            connectTimeoutId = setTimeout(connectWebSocket, retryDelay);
        }
      };
    }

    connectWebSocket();

    return () => {
      console.log("Cleaning up WebSocket effect for USB helper.");
      if (connectTimeoutId) clearTimeout(connectTimeoutId);
      if (wsRef.current) {
        wsRef.current.onopen = null;
        wsRef.current.onmessage = null;
        wsRef.current.onerror = null;
        wsRef.current.onclose = null; 
        if (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING) {
          wsRef.current.close(1000, "Component unmounting");
        }
        wsRef.current = null;
      }
      setIsHelperAppConnected(false);
      setIsNormalUsbConnected(false);
      setHidKey(initialHidKeyInfo); 
    };
  }, [userData]); 

  useEffect(() => {
    if (!userData) {
      if (JSON.stringify(availableModels) !== JSON.stringify(RESTRICTED_MODELS)) {
        setAvailableModels(RESTRICTED_MODELS);
      }
      return;
    }
    console.log(
      "availableModels useEffect - HID States: hidKey.isConnected:", hidKey.isConnected,
      "hidKey.path:", hidKey.path 
    );

    const loggedInWithSecurityKeyAtAuthTime = userData.securityKeyAuthenticated === true;
    let newAvailableModels = RESTRICTED_MODELS;
    let reasonForChange = "Default: Restricted models.";

    console.log(
      "Model Availability Check:",
      { loggedInWithSecurityKeyAtAuthTime },
      { securityKeyStatus }, 
      { isNormalUsbConnected },
      { isSecurityKeyHidConnected: hidKey.isConnected }, 
      { isHelperAppConnected },
      { currentModels: Object.keys(availableModels) }
    );

    if (loggedInWithSecurityKeyAtAuthTime) {
      newAvailableModels = ALL_MODELS;
      reasonForChange = "Logged in with an active security key.";
    } else {
      if (hidKey.isConnected && isHelperAppConnected) {
        newAvailableModels = ALL_MODELS;
        reasonForChange = "Security Key (HID) connected (email/password login).";
      } else if (isNormalUsbConnected && isHelperAppConnected) {
        newAvailableModels = ALL_MODELS;
        reasonForChange = "Normal USB connected (email/password login).";
      } else {
        newAvailableModels = RESTRICTED_MODELS;
        if (!isHelperAppConnected && initialLoadComplete.current) {
            reasonForChange = "USB Helper not connected. Model access restricted.";
        } else if (isHelperAppConnected && !isNormalUsbConnected && !hidKey.isConnected && initialLoadComplete.current) {
            reasonForChange = "No recognized USB device connected. Model access restricted.";
        } else {
            reasonForChange = "Default for email/password login without recognized USB device.";
        }
      }
    }
    
    if (JSON.stringify(availableModels) !== JSON.stringify(newAvailableModels)) {
        console.log(`Setting new available models due to: ${reasonForChange}. New models: ${Object.keys(newAvailableModels).join(', ')}`);
        setAvailableModels(newAvailableModels);
        if (JSON.stringify(newAvailableModels) === JSON.stringify(ALL_MODELS) && JSON.stringify(availableModels) !== JSON.stringify(ALL_MODELS)) {
            toast.success("Full model access enabled. " + reasonForChange);
        } else if (JSON.stringify(newAvailableModels) === JSON.stringify(RESTRICTED_MODELS) && JSON.stringify(availableModels) !== JSON.stringify(RESTRICTED_MODELS)) {
            toast.error("Model access restricted. " + reasonForChange);
        }
    } else {
         console.log(`Available models did not change (${Object.keys(availableModels).join(', ')}). Reason: ${reasonForChange}`);
    }

  }, [userData, securityKeyStatus, isNormalUsbConnected, hidKey, isHelperAppConnected, availableModels, initialLoadComplete]);


  useEffect(() => {
    if (!userData?.hasSecurityKey || !userData?.securityKeyAuthenticated) {
      return; 
    }
    console.log("Setting up security key monitoring (WebAuthn API)");
    const checkKeyStatus = async () => {
      if (keyCheckInProgress.current) return;
      keyCheckInProgress.current = true;
      try {
        const isConnected = await checkSecurityKeyStatus(userData.username);
        console.log("Security key status check result (WebAuthn API):", isConnected, "Current state:", securityKeyStatus);
        if (isConnected !== securityKeyStatus) {
          console.log("Security key status (WebAuthn API) changed from", securityKeyStatus, "to", isConnected);
          setSecurityKeyStatus(isConnected);
        }
      } catch (error) {
        console.error('Error checking security key status (WebAuthn API):', error);
      } finally {
        keyCheckInProgress.current = false;
      }
    };
    checkKeyStatus();
    securityKeyDetectionInterval.current = setInterval(checkKeyStatus, KEY_CHECK_INTERVAL);
    const handleKeyPress = (event: KeyboardEvent) => {
      if (event.altKey && event.key === 'k') {
        const newKeyState = !securityKeyStatus;
        console.log("Simulating securityKeyStatus (WebAuthn API) change:", newKeyState);
        setSecurityKeyStatus(newKeyState);
      }
    };
    window.addEventListener('keydown', handleKeyPress);
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'securityKeyConnected') { 
        const newState = e.newValue === 'true';
        if (newState !== securityKeyStatus) {
          setSecurityKeyStatus(newState);
        }
      }
    };
    window.addEventListener('storage', handleStorageChange);
    return () => {
      if (securityKeyDetectionInterval.current) {
        clearInterval(securityKeyDetectionInterval.current);
      }
      window.removeEventListener('keydown', handleKeyPress);
      window.removeEventListener('storage', handleStorageChange);
    };
  }, [userData, securityKeyStatus]);

  if (error) return <div>{error.message}</div>;

  if (!userData) {
    return (
        <div className="flex items-center justify-center min-h-screen">
          <div className="animate-spin rounded-xl h-8 w-8 border-t-2 border-b-2 border-primary"></div>
        </div>
    );
  }

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
"use client";

import { modelID } from "@/ai/providers";
import { useChat } from "@ai-sdk/react";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { toast } from 'sonner';
import { io, Socket } from "socket.io-client";
import { Textarea } from "@/components/textarea";
import { ProjectOverview } from "@/components/project-overview";
import { Messages } from "@/components/messages";
import { Header } from "@/components/header";
import {
  checkSecurityKeyStatus,
  requestSecurityKeyAccess,
  isWebUSBSupported
} from "@/app/utils/webauthn";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

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

  const [isNormalUsbConnected, setIsNormalUsbConnected] = useState<boolean>(false);
  const [hidKey, setHidKey] = useState<HidKeyInfo>(initialHidKeyInfo);
  const hidKeyRef = useRef(hidKey);
  useEffect(() => {
    hidKeyRef.current = hidKey;
    console.log("STATE TRACE: hidKey changed to:", hidKey, "and hidKeyRef updated.");
  }, [hidKey]);

  const [isHelperAppConnected, setIsHelperAppConnected] = useState<boolean>(false);
  const wsRef = useRef<WebSocket | null>(null);
  const socketIoRef = useRef<Socket | null>(null);
  const securityKeyDetectionInterval = useRef<NodeJS.Timeout | null>(null);
  const keyCheckInProgress = useRef<boolean>(false);
  const initialLoadComplete = useRef<boolean>(false);
  const webUSBSupported = useRef<boolean>(false);
  const hasLoggedWebSocketErrorRef = useRef<boolean>(false);

  const [isPinModalOpen, setIsPinModalOpen] = useState<boolean>(false);
  const [enteredPin, setEnteredPin] = useState<string>("");
  const [pinVerificationError, setPinVerificationError] = useState<string | null>(null);

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
          router.push("/");
          return;
        }
        setUserData(sessionUserData as UserData);
        // The securityKeyStatus state has been removed and is now derived from userData.
        if (!initialLoadComplete.current) {
            initialLoadComplete.current = true;
        }
      } catch (err) {
        console.error('Error checking authentication:', err);
        toast.error('Session error. Please login again.');
        router.push("/");
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
        hasConnectedSuccessfully = true;
        if (connectTimeoutId) clearTimeout(connectTimeoutId);
        console.log("Connected to USB helper WebSocket.");
        setIsHelperAppConnected(true);
        // Show toast only if the helper was not previously connected in this session
        if (!sessionStorage.getItem('usbHelperConnected')) {
            toast.success("USB Helper: Connected");
            sessionStorage.setItem('usbHelperConnected', 'true');
        }

        // Send the auth token to the detector script for user identification
        if (userData?.authToken) {
          console.log("Sending auth token to USB helper...");
          socket.send(JSON.stringify({
            type: 'auth',
            token: userData.authToken
          }));
        }
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
              // This case is now deprecated. The backend will handle model unlocking
              // and provide the necessary user feedback via Socket.IO events.
              console.log("FRONTEND: Received deprecated SECURITY_KEY_HID_CONNECTED event:", message);
              // The toast has been removed to prevent duplicate notifications.
              break;
            case "SECURITY_KEY_HID_DISCONNECTED":
              console.log("FRONTEND: Processing SECURITY_KEY_HID_DISCONNECTED event:", message);
              // If the user didn't log in with a key, a disconnect event should restrict models.
              // Always restrict models on disconnect, regardless of initial auth method.
              setAvailableModels(RESTRICTED_MODELS);
              toast.error("Security Key disconnected. Model access restricted.");
              // Also update the local hidKey state for any other UI indicators
              setHidKey(initialHidKeyInfo);
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
           sessionStorage.removeItem('usbHelperConnected'); // Clear the flag on disconnect
        }
        setIsHelperAppConnected(false);
        setIsNormalUsbConnected(false);
        if (!event.wasClean) {
            console.warn("WebSocket closed uncleanly. HID key state might be stale if detector crashed.");
        }
        if (wsRef.current === socket) {
          wsRef.current = null;
        }
        if (userData && event.code !== 1000) { // If not a clean, intentional close
            const currentDelay = Math.min(retryDelay * Math.pow(2, (connectTimeoutId ? 1 : 0)), 30000); // Exponential backoff up to 30s
            console.log(`WebSocket closed unexpectedly. Will attempt to reconnect in ${currentDelay / 1000}s.`);
            if (connectTimeoutId) clearTimeout(connectTimeoutId);
            connectTimeoutId = setTimeout(connectWebSocket, currentDelay);
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
    if (!userData || !userData.authToken) return;

    // Establish connection to the backend Socket.IO server
    const newSocket = io("http://localhost:5000");
    socketIoRef.current = newSocket;

    newSocket.on("connect", () => {
      console.log("Connected to backend Socket.IO server.");
      // Join the user-specific room
      newSocket.emit("join", { auth_token: userData.authToken });
    });

    newSocket.on("joined_room", (data) => {
      console.log(`Successfully joined room: ${data.room.substring(0, 10)}...`);
    });

    newSocket.on("models_unlocked", (data) => {
      console.log("Received models_unlocked event:", data);
      if (data.requires_pin) {
        console.log("PIN required for this key. Opening PIN modal.");
        setPinVerificationError(null); // Clear previous errors
        setEnteredPin(""); // Clear previous pin
        setIsPinModalOpen(true);
      } else {
        toast.success(data.message || "Security key verified. Full models enabled.");
        setAvailableModels(ALL_MODELS);
      }
    });

    newSocket.on("pin_verified", (data) => {
        console.log("PIN verification successful:", data);
        toast.success(data.message || "PIN verified. Full models enabled.");
        setIsPinModalOpen(false);
        setEnteredPin("");

        // Persist the authenticated state to survive page reloads
        if (userData) {
            const updatedUserData = {
                ...userData,
                securityKeyAuthenticated: true,
            };
            setUserData(updatedUserData);
            sessionStorage.setItem('user', JSON.stringify(updatedUserData));
        }
        setAvailableModels(ALL_MODELS);
    });

    newSocket.on("pin_incorrect", (data) => {
        console.error("Received pin_incorrect event:", data);
        setPinVerificationError(data.message || "The PIN entered is incorrect. Please try again.");
    });

    newSocket.on("key_mismatch_error", (data) => {
      console.error("Received key_mismatch_error event:", data);
      toast.error(data.message || "Security key does not belong to this user.");
    });

    // Handle disconnection
    newSocket.on("disconnect", () => {
      console.log("Disconnected from backend Socket.IO server.");
    });

    // Cleanup on component unmount
    return () => {
      if (socketIoRef.current) {
        socketIoRef.current.disconnect();
        socketIoRef.current = null;
      }
    };
  }, [userData]);


  // This useEffect now only sets the initial model availability when the user data is loaded.
  useEffect(() => {
    if (!userData) {
      setAvailableModels(RESTRICTED_MODELS);
      return;
    }

    const loggedInWithSecurityKeyAtAuthTime = userData.securityKeyAuthenticated === true;

    if (loggedInWithSecurityKeyAtAuthTime) {
      setAvailableModels(ALL_MODELS);
      // This toast is now redundant because the pin_verified handler shows a more specific one.
      // We keep the logic to set models but remove the generic toast.
    } else {
      setAvailableModels(RESTRICTED_MODELS);
    }
  }, [userData]);



  const handlePinSubmit = () => {
    if (socketIoRef.current && enteredPin && userData?.authToken) {
      console.log("Emitting verify_pin event with PIN and auth token.");
      setPinVerificationError(null); // Clear error on new attempt
      socketIoRef.current.emit("verify_pin", {
        pin: enteredPin,
        auth_token: userData.authToken
      });
    } else if (!enteredPin) {
        setPinVerificationError("PIN cannot be empty.");
    }
  };

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
        <Dialog open={isPinModalOpen} onOpenChange={(isOpen) => {
            if (!isOpen) {
                setEnteredPin("");
                setPinVerificationError(null);
            }
            setIsPinModalOpen(isOpen);
        }}>
          <DialogContent className="sm:max-w-[425px] font-montserrat" onEscapeKeyDown={() => setIsPinModalOpen(false)}>
            <DialogHeader>
              <DialogTitle>Security Key PIN Required</DialogTitle>
              <DialogDescription>
                Please enter the PIN for your security key to unlock full model access.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-4 items-center gap-4">
                <Input
                  id="pin"
                  type="password"
                  value={enteredPin}
                  onChange={(e) => setEnteredPin(e.target.value)}
                  placeholder="Enter PIN"
                  className="col-span-4"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handlePinSubmit();
                    }
                  }}
                />
              </div>
              {pinVerificationError && (
                <p className="text-sm text-red-500 px-1">{pinVerificationError}</p>
              )}
            </div>
            <DialogFooter>
               <Button
                  onClick={() => {
                    setIsPinModalOpen(false);
                  }}
                  variant="outline"
              >
                Cancel
              </Button>
              <Button onClick={handlePinSubmit}>Submit</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

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
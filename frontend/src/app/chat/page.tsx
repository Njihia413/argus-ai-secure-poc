"use client";

import { modelID } from "@/ai/providers";
import { useChat } from "@ai-sdk/react";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { API_URL } from "@/app/utils/constants";
import { toast } from 'sonner';
import { io, Socket } from "socket.io-client";
import { Textarea } from "@/components/textarea";
import { ProjectOverview } from "@/components/project-overview";
import { Messages } from "@/components/messages";
import { Header } from "@/components/header";
import { ThreeDots } from "react-loader-spinner";
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
import { getCachedMachineId } from "@/app/utils/machine-fingerprint";

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

// Fallback shown only while the initial /api/access/models request is in-flight.
const EMPTY_MODELS: ModelDict = {};

const DEFAULT_MODEL_ID: modelID = "openai/gpt-oss-20b";
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
  const [availableModels, setAvailableModels] = useState<ModelDict>(EMPTY_MODELS);
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

  const [fingerprintVersion, setFingerprintVersion] = useState<number>(0);
  const [accessReady, setAccessReady] = useState<boolean>(false);
  const [capabilitiesOpen, setCapabilitiesOpen] = useState<boolean>(false);
  const [capabilities, setCapabilities] = useState<{
    tier: string
    models: { slug: string; display_name: string }[]
    apps: { slug: string; display_name: string; features: { slug: string; display_name: string; allowed: boolean }[] }[]
  }>({ tier: "none", models: [], apps: [] });

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
    experimental_prepareRequestBody: ({ messages }) => {
      const machineId = getCachedMachineId();
      // Read fresh at submit time — userData closure can be stale.
      const stored = JSON.parse(sessionStorage.getItem("user") || "{}");
      return {
        messages,
        selectedModel,
        authToken: stored.authToken || userData?.authToken,
        machineId,
      };
    },
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
              // Tell the backend to clear security_key_verified on the session,
              // THEN refetch models. Without the backend call, get_access_tier()
              // would still see security_key_verified=True and keep the user at
              // their elevated tier even after the key is unplugged.
              {
                const stored = JSON.parse(sessionStorage.getItem("user") || "{}");
                if (stored.authToken) {
                  fetch(`${API_URL}/security_key/disconnect`, {
                    method: "POST",
                    headers: { Authorization: `Bearer ${stored.authToken}` },
                  })
                    .catch((err) => console.error("Failed to clear backend key state:", err))
                    .finally(() => {
                      stored.securityKeyAuthenticated = false;
                      sessionStorage.setItem("user", JSON.stringify(stored));
                      setUserData(stored);
                    });
                }
              }
              toast.error("Security Key disconnected. Model access restricted.");
              // Also update the local hidKey state for any other UI indicators
              setHidKey(initialHidKeyInfo);
              break;
            case "MACHINE_FINGERPRINT":
              // Store the workstation fingerprint so admin pages can use it for machine binding.
              // This ensures the bound identity is the workstation running usb_detector.py,
              // not the Flask server — which matters in multi-machine enterprise deployments.
              sessionStorage.setItem("workstation_fingerprint", JSON.stringify({
                machine_id: message.machine_id,
                components: message.components,
              }));
              console.log("FRONTEND: Workstation fingerprint stored from usb_detector:", message.machine_id?.slice(0, 16));
              setFingerprintVersion((v) => v + 1);
              setAccessReady(true);
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

    // Connect Socket.IO directly to Flask backend (not through Next.js proxy,
    // which only rewrites HTTP requests and doesn't handle WebSocket upgrades)
    const newSocket = io(process.env.NEXT_PUBLIC_FLASK_URL || "http://localhost:5000");
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
        // Flip the session flag; the useEffect watching userData will re-fetch
        // /api/access/models and render the newly-available set.
        const stored = JSON.parse(sessionStorage.getItem("user") || "{}");
        if (stored.authToken) {
          stored.securityKeyAuthenticated = true;
          sessionStorage.setItem("user", JSON.stringify(stored));
          setUserData(stored);
        }
      }
    });

    newSocket.on("pin_verified", (data) => {
        console.log("PIN verification successful:", data);
        toast.success(data.message || "PIN verified. Full models enabled.");
        setIsPinModalOpen(false);
        setEnteredPin("");

        // Persist the authenticated state to survive page reloads. The
        // userData change triggers a re-fetch of the allowed model list.
        if (userData) {
            const updatedUserData = {
                ...userData,
                securityKeyAuthenticated: true,
            };
            setUserData(updatedUserData);
            sessionStorage.setItem('user', JSON.stringify(updatedUserData));
        }
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


  // Hold the initial access fetch until the workstation fingerprint has
  // arrived (or a short grace period elapses). Without this, the page fires
  // /api/access/models before usb_detector delivers the machine_id — the
  // backend returns the key_unbound tier, then a second request upgrades
  // the user to key_bound, and they see a "flash" of the smaller model set.
  useEffect(() => {
    if (!userData?.authToken) {
      setAccessReady(false);
      return;
    }
    if (accessReady) return;
    const timer = setTimeout(() => setAccessReady(true), 1500);
    return () => clearTimeout(timer);
  }, [userData, accessReady]);

  // Fetch the authoritative list of models from the backend. The backend
  // intersects the session's tier with the user's role permissions; this page
  // just renders what it's told. Re-fetch whenever userData changes (login /
  // logout / key verification flipping securityKeyAuthenticated).
  useEffect(() => {
    if (!userData?.authToken) {
      setAvailableModels(EMPTY_MODELS);
      return;
    }
    if (!accessReady) return;

    const fetchModels = async () => {
      try {
        const fp = sessionStorage.getItem("workstation_fingerprint");
        const machineId = fp ? (JSON.parse(fp)?.machine_id ?? "") : "";
        const res = await fetch(`${API_URL}/access/models`, {
          headers: {
            Authorization: `Bearer ${userData.authToken}`,
            ...(machineId ? { "X-Machine-Id": machineId } : {}),
          },
        });
        if (!res.ok) {
          console.error("Failed to fetch allowed models:", res.status);
          setAvailableModels(EMPTY_MODELS);
          return;
        }
        const body: { tier: string; models: { slug: string; display_name: string }[] } = await res.json();
        const dict: ModelDict = {};
        for (const m of body.models) {
          (dict as Record<string, string>)[m.slug] = m.display_name;
        }
        setAvailableModels(dict);
      } catch (err) {
        console.error("Error fetching allowed models:", err);
        setAvailableModels(EMPTY_MODELS);
      }
    };

    fetchModels();
  }, [userData, fingerprintVersion, accessReady]);


  // Capabilities: fetch allowed models + apps (+features per app) so the user
  // can see at a glance what they can do on this workstation without having
  // to probe the AI with trial-and-error prompts.
  useEffect(() => {
    if (!userData?.authToken) {
      setCapabilities({ tier: "none", models: [], apps: [] });
      return;
    }
    if (!accessReady) return;

    const fetchCapabilities = async () => {
      try {
        const fp = sessionStorage.getItem("workstation_fingerprint");
        const machineId = fp ? (JSON.parse(fp)?.machine_id ?? "") : "";
        const headers: HeadersInit = {
          Authorization: `Bearer ${userData.authToken}`,
          ...(machineId ? { "X-Machine-Id": machineId } : {}),
        };

        const [modelsRes, appsRes] = await Promise.all([
          fetch(`${API_URL}/access/models`, { headers }),
          fetch(`${API_URL}/access/applications`, { headers }),
        ]);

        const modelsBody = modelsRes.ok
          ? await modelsRes.json()
          : { tier: "none", models: [] };
        const appsBody = appsRes.ok
          ? await appsRes.json()
          : { tier: modelsBody.tier, applications: [] };

        const appsWithFeatures = await Promise.all(
          (appsBody.applications || []).map(async (a: { slug: string; display_name: string }) => {
            const fRes = await fetch(`${API_URL}/access/applications/${a.slug}/features`, { headers });
            const fBody = fRes.ok ? await fRes.json() : { features: [] };
            return {
              slug: a.slug,
              display_name: a.display_name,
              features: (fBody.features || []).map((f: { slug: string; display_name: string }) => ({
                ...f,
                allowed: true,
              })),
            };
          })
        );

        setCapabilities({
          tier: modelsBody.tier || appsBody.tier || "none",
          models: modelsBody.models || [],
          apps: appsWithFeatures,
        });
      } catch (err) {
        console.error("Error fetching capabilities:", err);
      }
    };

    fetchCapabilities();
  }, [userData, fingerprintVersion, accessReady]);


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

  useEffect(() => {
    if (!error) return;
    console.error("Chat error:", error);
    let parsed: { error?: string; reason?: string } = {};
    try { parsed = JSON.parse(error.message); } catch { /* leave empty */ }
    if (parsed.error === "Missing auth token" || /401/.test(error.message)) {
      sessionStorage.removeItem("user");
      router.push("/");
      return;
    }
    toast.error(parsed.reason || parsed.error || error.message);
  }, [error, router]);

  if (!userData) {
    return (
        <div className="flex items-center justify-center min-h-screen">
          <ThreeDots height="40" width="40" color="currentColor" ariaLabel="loading" />
        </div>
    );
  }

  const hasMessages = messages.length > 0;

  const tierLabel = (t: string) =>
    t === "key_bound"
      ? "Key + bound machine"
      : t === "key_unbound"
      ? "Key verified"
      : "Password only";
  const tierColor = (t: string) =>
    t === "key_bound"
      ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300"
      : t === "key_unbound"
      ? "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300"
      : "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";

  return (
      <div className="h-dvh flex flex-col font-montserrat w-full stretch">
        <Header />

        <button
          onClick={() => setCapabilitiesOpen(true)}
          className="fixed top-5 right-32 z-50 flex items-center gap-2 rounded-full border border-zinc-300 dark:border-zinc-700 bg-white/80 dark:bg-zinc-900/80 backdrop-blur px-3 py-1.5 text-xs shadow-sm hover:bg-white dark:hover:bg-zinc-900 transition"
          aria-label="What you can do here"
        >
          Capabilities
          <span className={`ml-1 px-1.5 py-0.5 rounded text-[10px] font-medium ${accessReady ? tierColor(capabilities.tier) : "bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400 animate-pulse"}`}>
            {accessReady ? tierLabel(capabilities.tier) : "Loading…"}
          </span>
        </button>

        <Dialog open={capabilitiesOpen} onOpenChange={setCapabilitiesOpen}>
          <DialogContent className="sm:max-w-lg font-montserrat max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>What you can do here</DialogTitle>
              <DialogDescription>
                Based on your access tier and role permissions on this workstation.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-6 py-2">
              <div>
                <div className="text-xs font-semibold uppercase text-muted-foreground mb-2">
                  Access tier
                </div>
                <span className={`inline-block px-2 py-1 rounded text-xs ${tierColor(capabilities.tier)}`}>
                  {tierLabel(capabilities.tier)}
                </span>
                <p className="text-xs text-muted-foreground mt-2">
                  {capabilities.tier === "none" &&
                    "Tap your security key to unlock more models. Bind it to this machine to unlock apps."}
                  {capabilities.tier === "key_unbound" &&
                    "Bind your key to this machine to unlock the full model set and your installed apps."}
                  {capabilities.tier === "key_bound" &&
                    "You're on a bound workstation — full access is available within your role."}
                </p>
              </div>

              <div>
                <div className="text-xs font-semibold uppercase text-muted-foreground mb-2">
                  Models ({capabilities.models.length})
                </div>
                {capabilities.models.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No models available.</p>
                ) : (
                  <ul className="space-y-1">
                    {capabilities.models.map((m) => (
                      <li key={m.slug} className="text-sm flex items-center gap-2">
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                        {m.display_name}
                        <span className="text-xs text-muted-foreground">· {m.slug}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div>
                <div className="text-xs font-semibold uppercase text-muted-foreground mb-2">
                  Apps on this machine you have access to ({capabilities.apps.length})
                </div>
                {capabilities.apps.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {capabilities.tier === "key_bound"
                      ? "No detected apps on this workstation yet."
                      : "App detection requires a bound machine."}
                  </p>
                ) : (
                  <div className="space-y-3">
                    {capabilities.apps.map((a) => (
                      <div key={a.slug} className="rounded-md border border-zinc-300 dark:border-zinc-700 p-3">
                        <div className="font-medium text-sm">{a.display_name}</div>
                        {a.features.length > 0 && (
                          <ul className="mt-2 space-y-1">
                            {a.features.map((f) => (
                              <li key={f.slug} className="text-xs text-muted-foreground flex items-center gap-2">
                                <span className="h-1 w-1 rounded-full bg-sky-500" />
                                {f.display_name}
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </DialogContent>
        </Dialog>

        {/* PIN Modal */}
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

        {hasMessages ? (
          <>
            <Messages messages={messages} isLoading={isLoading} status={status} />
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
                  tier={capabilities.tier as "none" | "key_unbound" | "key_bound"}
              />
            </form>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center px-4">
            <div className="max-w-xl w-full space-y-8">
              <ProjectOverview />
              <form onSubmit={handleSubmit}>
                <Textarea
                    selectedModel={selectedModel}
                    setSelectedModel={setSelectedModel}
                    handleInputChange={handleInputChange}
                    input={input}
                    isLoading={isLoading}
                    status={status}
                    stop={stop}
                    models={availableModels}
                    tier={capabilities.tier as "none" | "key_unbound" | "key_bound"}
                />
              </form>
            </div>
          </div>
        )}
      </div>
  );
}
"use client";

import { modelID } from "@/ai/providers";
import { useChat } from "@ai-sdk/react";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Textarea } from "@/components/textarea";
import { ProjectOverview } from "@/components/project-overview";
import { Messages } from "@/components/messages";
import { Header } from "@/components/header";
import { toast } from "sonner";
import { KeyRound, X } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {registerSecurityKey} from "@/app/utils/webauthn";


// Security key registration modal component
const SecurityKeyModal = ({
                            isOpen,
                            setIsOpen,
                            userData,
                            onRegisterSuccess,
                          }: {
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
  userData: any;
  onRegisterSuccess: () => void;
})  => {
  const [isRegistering, setIsRegistering] = useState(false);

  const handleRegisterSecurityKey = async () => {
    if (!userData || !userData.username) {
      toast.error("User information not available");
      return;
    }

    setIsRegistering(true);

    await registerSecurityKey(
        userData.username,
        (message) => {
          toast.success(message);
          setIsRegistering(false);
          onRegisterSuccess();
          setIsOpen(false);
        },
        (errorMessage) => {
          toast.error(errorMessage);
          setIsRegistering(false);
        }
    );
  };

  return (
      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent className="sm:max-w-md font-montserrat">
          <DialogHeader>
            <DialogTitle>Enhance Your Account Security</DialogTitle>
            <DialogDescription>
              Add a security key to protect your account against unauthorized access
              and phishing attacks.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="p-3 bg-amber-50 rounded-md border border-amber-200">
              <h3 className="text-amber-800 font-medium">Why Use a Security Key?</h3>
              <p className="text-amber-700 text-sm mt-1">
                Security keys provide significantly stronger protection than
                passwords alone. Even if your password is compromised, attackers
                cannot access your account without your physical security key.
              </p>
            </div>
            <div className="space-y-2 text-sm">
              <div className="p-3 bg-blue-50 rounded-md">
                <h4 className="font-medium text-blue-800">Compatible Devices</h4>
                <p className="text-blue-700 mt-1">
                  YubiKeys, Google Titan Security Keys, and most FIDO2-compatible
                  security keys
                </p>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button
                type="button"
                variant="secondary"
                onClick={() => setIsOpen(false)}
            >
              Remind Me Later
            </Button>
            <Button
                type="button"
                onClick={handleRegisterSecurityKey}
                className="gap-2"
                disabled={isRegistering}
            >
              <KeyRound className="h-4 w-4" />
              {isRegistering ? "Registering..." : "Register Security Key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
  );
};

export default function Page() {
  const router = useRouter();
  const [selectedModel, setSelectedModel] = useState("deepseek-r1-distill-llama-70b");
  const [userData, setUserData] = useState(null);
  const [hasSecurityKey, setHasSecurityKey] = useState(false);
  const [showSecurityKeyModal, setShowSecurityKeyModal] = useState(false);
  const [hasShownModal, setHasShownModal] = useState(false);

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
          const mockUser = {
            username: 'demo@example.com',
            firstName: 'Demo',
            lastName: 'User',
            hasSecurityKey: false
          };
          sessionStorage.setItem('user', JSON.stringify(mockUser));
          setUserData(mockUser);
          setHasSecurityKey(false);

          // Show security key modal for the mock user only if it hasn't been shown yet
          if (!hasShownModal) {
            setTimeout(() => {
              setShowSecurityKeyModal(true);
              setHasShownModal(true);  // Track that we've shown the modal
            }, 1500);
          }
        } else {
          setUserData(userData);
          setHasSecurityKey(userData.hasSecurityKey || false);

          // Show security key modal if user doesn't have one and it hasn't been shown yet
          if (!userData.hasSecurityKey && !hasShownModal) {
            // Delay showing modal for better UX
            setTimeout(() => {
              setShowSecurityKeyModal(true);
              setHasShownModal(true);  // Track that we've shown the modal
            }, 1500);
          }
        }
      } catch (err) {
        console.error('Error checking authentication:', err);
        // Create mock user instead of redirecting for demo purposes
        const mockUser = {
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
  }, [hasShownModal]);

  // Handle key registration success
  const handleKeyRegistrationSuccess = () => {
    setHasSecurityKey(true);

    // Update user data in session storage
    if (userData) {
      const updatedUser = { ...userData, hasSecurityKey: true };
      sessionStorage.setItem('user', JSON.stringify(updatedUser));
      setUserData(updatedUser);
    }
  };

  // Handler to show security modal
  const handleShowSecurityModal = () => {
    setShowSecurityKeyModal(true);
  };

  if (error) return <div>{error.message}</div>;

  if (!userData) {
    return (
        <div className="flex items-center justify-center min-h-screen">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary"></div>
        </div>
    );
  }

  return (
      <div className="h-dvh flex flex-col justify-center font-montserrat w-full stretch">
        <Header onShowSecurityModal={handleShowSecurityModal} />

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
          />
        </form>

        {/* Security key registration modal */}
        <SecurityKeyModal
            isOpen={showSecurityKeyModal}
            setIsOpen={setShowSecurityKeyModal}
            userData={userData}
            onRegisterSuccess={handleKeyRegistrationSuccess}
        />
      </div>
  );
}

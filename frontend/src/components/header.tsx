import Link from "next/link";
import { useEffect, useState } from "react";
import { User, Settings, LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { clearBindingData } from "@/app/utils/webauthn";

// Import ShadCN components
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { KeyRound } from "lucide-react";

// Define types for components
interface SecurityKeyRegistrationProps {
  userData: any;
  onRegisterSuccess: () => void;
}

// This component will be used to register a security key within the settings modal
const SecurityKeyRegistration = ({ userData, onRegisterSuccess }: SecurityKeyRegistrationProps) => {
  const [isRegistering, setIsRegistering] = useState(false);

  const handleRegisterSecurityKey = async () => {
    if (!userData || !userData.username) {
      toast.error("User information not available");
      return;
    }

    setIsRegistering(true);

    // Import the registerSecurityKey function dynamically to avoid circular dependencies
    const { registerSecurityKey } = await import("@/app/utils/webauthn");

    await registerSecurityKey(
        userData.username,
        (message) => {
          toast.success(message);
          setIsRegistering(false);
          onRegisterSuccess();
        },
        (errorMessage) => {
          toast.error(errorMessage);
          setIsRegistering(false);
        }
    );
  };

  return (
      <div className="space-y-4">
        <div className="p-3 bg-amber-50 rounded-md border border-amber-200">
          <h3 className="text-amber-800 font-medium">Why Use a Security Key?</h3>
          <p className="text-amber-700 text-sm mt-1">
            Security keys provide significantly stronger protection than passwords alone.
            Even if your password is compromised, attackers cannot access your account
            without your physical security key.
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

        <Button
            onClick={handleRegisterSecurityKey}
            className="w-full gap-2"
            disabled={isRegistering}
        >
          <KeyRound className="h-4 w-4" />
          {isRegistering ? "Registering..." : "Register Security Key"}
        </Button>
      </div>
  );
};

interface SecurityInformationProps {
  userData: any;
}

// This component shows security information when the user already has a security key
const SecurityInformation = ({ userData }: SecurityInformationProps) => {
  return (
      <div className="space-y-4">
        <div className="p-4 bg-green-50 rounded-md border border-green-200">
          <div className="flex items-center mb-2">
            <KeyRound className="h-5 w-5 text-green-600 mr-2" />
            <h3 className="text-green-800 font-medium">Account Secured</h3>
          </div>
          <p className="text-green-700 text-sm">
            Your account is protected with a security key. This adds an extra layer of
            protection against unauthorized access attempts.
          </p>
        </div>

        <div className="space-y-2">
          <div className="p-3 border rounded-md">
            <h4 className="font-medium">Security Details</h4>
            <div className="mt-2 text-sm space-y-2">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Username:</span>
                <span className="font-medium">{userData?.username}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Security Key Added:</span>
                <span className="font-medium">Yes</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last Verification:</span>
                <span className="font-medium">Today</span>
              </div>
            </div>
          </div>
        </div>

        <Button variant="outline" className="w-full">
          Manage Security Keys
        </Button>
      </div>
  );
};

interface SettingsModalProps {
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
  userData: any;
  onRegisterSuccess: () => void;
  hasSecurityKey: boolean;
  activeTab?: string;
}

// Settings Modal Component with Tabs
const SettingsModal = ({ isOpen, setIsOpen, userData, onRegisterSuccess, hasSecurityKey, activeTab }: SettingsModalProps) => {
  return (
      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent className="sm:max-w-md font-montserrat">
          <DialogHeader>
            <DialogTitle>Settings</DialogTitle>
            <DialogDescription>
              Manage your account settings and preferences
            </DialogDescription>
          </DialogHeader>

          <Tabs defaultValue={activeTab || "general"} className="w-full">
            <TabsList className="grid grid-cols-3 mb-4 w-full">
              <TabsTrigger value="general" className="flex-1">General</TabsTrigger>
              <TabsTrigger value="profile" className="flex-1">Profile</TabsTrigger>
              <TabsTrigger value="security" className="flex-1">Security</TabsTrigger>
            </TabsList>

            {/* General Tab */}
            <TabsContent value="general" className="space-y-4">
              <div className="space-y-4">
                <div className="p-3 bg-muted rounded-md">
                  <h3 className="font-medium">App Preferences</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Customize your application experience
                  </p>
                </div>

                <div className="grid gap-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Dark Mode</span>
                    <Button variant="outline" size="sm">Toggle</Button>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Notifications</span>
                    <Button variant="outline" size="sm">Configure</Button>
                  </div>
                </div>
              </div>
            </TabsContent>

            {/* Profile Tab */}
            <TabsContent value="profile" className="space-y-4">
              <div className="flex flex-col items-center space-y-2">
                <div className="h-20 w-20 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-2xl font-bold">
                  {userData?.firstName?.[0] || ""}
                  {userData?.lastName?.[0] || ""}
                </div>
                <h3 className="font-medium">{userData?.firstName} {userData?.lastName}</h3>
                <p className="text-sm text-muted-foreground">{userData?.username}</p>
              </div>

              <div className="grid gap-2">
                <Button variant="outline" size="sm">
                  Edit Profile
                </Button>
                <Button variant="outline" size="sm">
                  Change Password
                </Button>
              </div>
            </TabsContent>

            {/* Security Tab */}
            <TabsContent value="security" className="space-y-4">
              {hasSecurityKey ? (
                  <SecurityInformation userData={userData} />
              ) : (
                  <SecurityKeyRegistration
                      userData={userData}
                      onRegisterSuccess={onRegisterSuccess}
                  />
              )}
            </TabsContent>
          </Tabs>

          <DialogFooter>
            <Button
                variant="outline"
                onClick={() => setIsOpen(false)}
                className="border-black bg-white hover:bg-gray-50"
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
  );
};

// Add the interface for Header props
interface HeaderProps {
  onShowSecurityModal?: () => void;  // Make it optional with the ? mark
}

export const Header = ({ onShowSecurityModal }: HeaderProps) => {
  const router = useRouter();
  const [userData, setUserData] = useState(null);
  const [hasSecurityKey, setHasSecurityKey] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [activeSettingsTab, setActiveSettingsTab] = useState("general");

  // Check user data on component mount
  useEffect(() => {
    const checkUserData = () => {
      const storedUser = sessionStorage.getItem('user');
      if (storedUser) {
        const parsedUser = JSON.parse(storedUser);
        setUserData(parsedUser);
        setHasSecurityKey(parsedUser.hasSecurityKey || false);
      }
    };

    checkUserData();
    // Listen for storage events (in case user data changes in another tab)
    window.addEventListener('storage', checkUserData);
    return () => window.removeEventListener('storage', checkUserData);
  }, []);

  // Handle logout
  const handleLogout = () => {
    clearBindingData();
    sessionStorage.removeItem('user');
    router.push('/login');
  };

  // Handle security key registration success
  const handleKeyRegistrationSuccess = () => {
    setHasSecurityKey(true);

    // Update user data in session storage
    if (userData) {
      const updatedUser = { ...userData, hasSecurityKey: true };
      sessionStorage.setItem('user', JSON.stringify(updatedUser));
      setUserData(updatedUser);
    }
  };

  // Open settings modal with specific tab
  const openSettingsWithTab = (tab) => {
    setActiveSettingsTab(tab);
    setShowSettingsModal(true);
  };

  // If onShowSecurityModal is provided, use it to show the security tab
  const handleShowSecurity = () => {
    if (onShowSecurityModal) {
      // Use the prop if provided
      onShowSecurityModal();
    } else {
      // Otherwise use the default behavior
      openSettingsWithTab("security");
    }
  };

  return (
      <div className="fixed right-0 left-0 w-full top-0 bg-white dark:bg-zinc-950 z-50">
        <div className="flex justify-between items-center p-4">
          <div className="flex flex-row items-center gap-2 shrink-0 ">
          <span className="jsx-e3e12cc6f9ad5a71 flex flex-row items-center gap-2 home-links">
            <Link
                className="text-zinc-800 dark:text-zinc-100 -translate-y-[.5px]"
                rel="noopener"
                target="_blank"
                href="/"
            >
              <img src="/assets/images/Logo-No-Bg.png" className="h-8" alt="ArgusLogo" />
            </Link>
            <div className="jsx-e3e12cc6f9ad5a71 w-4 text-lg text-center text-zinc-300 dark:text-zinc-600">
              <svg
                  data-testid="geist-icon"
                  height={16}
                  strokeLinejoin="round"
                  viewBox="0 0 16 16"
                  width={16}
                  style={{ color: "currentcolor" }}
              >
                <path
                    fillRule="evenodd"
                    clipRule="evenodd"
                    d="M4.01526 15.3939L4.3107 14.7046L10.3107 0.704556L10.6061 0.0151978L11.9849 0.606077L11.6894 1.29544L5.68942 15.2954L5.39398 15.9848L4.01526 15.3939Z"
                    fill="currentColor"
                />
              </svg>
            </div>
            <div className="jsx-e3e12cc6f9ad5a71 flex flex-row items-center gap-4">
              <Link className="flex flex-row items-end gap-2" target="_blank" href="/">
                Argus AI
              </Link>
            </div>
          </span>
          </div>

          {/* User profile section - simplified */}
          {userData && (
              <div className="flex items-center font">
                {/* User avatar/dropdown menu - without arrow */}
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <div className="cursor-pointer">
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border shadow bg-primary text-primary-foreground">
                        {userData?.firstName?.[0] || ""}
                        {userData?.lastName?.[0] || ""}
                      </div>
                    </div>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="font-montserrat">
                    <DropdownMenuLabel>My Account</DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => openSettingsWithTab("profile")}>
                      <User className="mr-2 h-4 w-4" />
                      <span>Profile</span>
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => openSettingsWithTab("general")}>
                      <Settings className="mr-2 h-4 w-4" />
                      <span>Settings</span>
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={handleShowSecurity}>
                      <KeyRound className="mr-2 h-4 w-4" />
                      <span>Security</span>
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={handleLogout}>
                      <LogOut className="mr-2 h-4 w-4" />
                      <span>Log out</span>
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>

                {/* Settings Modal */}
                <SettingsModal
                    isOpen={showSettingsModal}
                    setIsOpen={setShowSettingsModal}
                    userData={userData}
                    onRegisterSuccess={handleKeyRegistrationSuccess}
                    hasSecurityKey={hasSecurityKey}
                    activeTab={activeSettingsTab}
                />
              </div>
          )}
        </div>
      </div>
  );
};

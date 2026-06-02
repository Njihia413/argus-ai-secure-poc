import Link from "next/link";
import { useEffect, useState } from "react";
import { User, Settings, LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { clearBindingData } from "@/app/utils/webauthn";
import axios from "axios";
import { API_URL } from "@/app/utils/constants";
import { toast } from "sonner";

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
import { KeyRound } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";

// Define the UserData interface
interface UserData {
  username: string;
  firstName?: string;
  lastName?: string;
  hasSecurityKey: boolean;
  role: string;
}

interface SettingsModalProps {
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
  userData: UserData | null;
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
            <TabsList className="grid grid-cols-2 mb-4 w-full">
              <TabsTrigger value="general" className="flex-1">General</TabsTrigger>
              <TabsTrigger value="profile" className="flex-1">Profile</TabsTrigger>
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
                <div className="h-20 w-20 rounded-xl bg-primary flex items-center justify-center text-primary-foreground text-2xl font-bold">
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
          </Tabs>

          <DialogFooter>
            <Button variant="outline" onClick={() => setIsOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
  );
};

export const Header = () => {
  const router = useRouter();
  const [userData, setUserData] = useState<UserData | null>(null);
  const [hasSecurityKey, setHasSecurityKey] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [activeSettingsTab, setActiveSettingsTab] = useState("general");

  // Check user data on component mount
  useEffect(() => {
    const checkUserData = () => {
      const storedUser = sessionStorage.getItem('user');
      if (storedUser) {
        const parsedUser = JSON.parse(storedUser);
        setUserData(parsedUser as UserData);
        setHasSecurityKey(parsedUser.hasSecurityKey || false);
      }
    };

    checkUserData();
    // Listen for storage events (in case user data changes in another tab)
    window.addEventListener('storage', checkUserData);
    return () => window.removeEventListener('storage', checkUserData);
  }, []);

  // Handle logout
  const handleLogout = async () => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");

    if (!userInfo || !userInfo.authToken) {
      toast.error("You need to log in");
      router.push("/");
      return;
    }

    try {
      await axios.post(`${API_URL}/logout`, {}, {
        headers: {
          Authorization: `Bearer ${userInfo.authToken}`,
        },
      });
      toast.success('Logged out successfully');
    } catch (error) {
      toast.error('Logout failed');
    } finally {
      clearBindingData();
      sessionStorage.removeItem('user');
      router.push('/');
    }
  };

  // Handle security key registration success
  const handleKeyRegistrationSuccess = () => {
    setHasSecurityKey(true);

    // Update user data in session storage
    if (userData) {
      const updatedUser: UserData = { ...userData, hasSecurityKey: true };
      sessionStorage.setItem('user', JSON.stringify(updatedUser));
      setUserData(updatedUser);
    }
  };

  // Open settings modal with specific tab
  const openSettingsWithTab = (tab: string) => {
    setActiveSettingsTab(tab);
    setShowSettingsModal(true);
  };

  return (
      <div className="fixed right-0 left-0 w-full top-0 bg-white dark:bg-zinc-900 z-50 border-b border-zinc-200 dark:border-zinc-800 font-montserrat">
        <div className="flex justify-between items-center p-4">
          <div className="flex items-center space-x-2">
            <Link href="/dashboard" className="flex items-center space-x-2">
              <span className="text-lg md:text-xl font-bold text-zinc-900 dark:text-white">
               Argus AI
              </span>
            </Link>
          </div>

          {/* User profile section - simplified */}
          {userData && (
              <div className="flex items-center font gap-2">
                <ThemeToggle />
                {/* User avatar/dropdown menu - without arrow */}
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <div className="cursor-pointer">
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border shadow bg-primary text-primary-foreground">
                        {userData?.firstName?.[0] || ""}
                        {userData?.lastName?.[0] || ""}
                      </div>
                    </div>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="font-montserrat">
                    <DropdownMenuLabel className="flex flex-col gap-0.5">
                      <span>{userData?.firstName} {userData?.lastName}</span>
                      {userData?.role && (
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-normal">
                          {userData.role.replace(/_/g, " ")}
                        </span>
                      )}
                    </DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => openSettingsWithTab("profile")}>
                      <User className="mr-2 h-4 w-4" />
                      <span>Profile</span>
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => openSettingsWithTab("general")}>
                      <Settings className="mr-2 h-4 w-4" />
                      <span>Settings</span>
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

"use client"

import React, { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Eye, EyeOff, ShieldCheck, Key, AlertTriangle } from 'lucide-react'
import axios from "axios"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogDescription
} from "@/components/ui/dialog"
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle
} from "@/components/ui/alert-dialog"

import {
    authenticateWithSecurityKey,
    clearBindingData,
    initializeSecurityKeyStatus
} from "@/app/utils/webauthn"
import { API_URL } from "@/app/utils/constants"

// Security key verification component for second factor authentication
const SecurityKeyPrompt = ({
                               username,
                               authToken,
                               bindingNonce,
                               riskScore,
                               onSuccess,
                               onCancel,
                               setLoadingStatus,
                               setIsLoading
                           }: {
    username: string,
    authToken: string,
    bindingNonce: string,
    riskScore: number,
    onSuccess: (userData: any) => void,
    onCancel: () => void,
    setLoadingStatus: (status: string) => void,
    setIsLoading: (isLoading: boolean) => void
}) => {
    const [isVerifying, setIsVerifying] = useState(false)
    const [securityKeyError, setSecurityKeyError] = useState("")

    const handleVerify = async () => {
        if (isVerifying) {
            console.log('Verification already in progress, ignoring duplicate request');
            return;
        }

        setIsVerifying(true)
        setSecurityKeyError("")
        setLoadingStatus("Verifying Security Key...")

        try {
            await authenticateWithSecurityKey(
                username,
                authToken,
                bindingNonce,
                (userData) => {
                    setIsVerifying(false)
                    onSuccess(userData)
                },
                (errorMessage) => {
                    console.log("Security key error:", errorMessage);
                    setSecurityKeyError(errorMessage);
                    setIsVerifying(false);
                    setLoadingStatus("Logging in...");
                    setIsLoading(false); // Reset parent loading state

                    toast.error(errorMessage);
                }
            )
        } catch (err: any) {
            console.error("Unhandled error in security key verification:", err);
            const errorMsg = err?.message || "An unexpected error occurred";
            setSecurityKeyError(errorMsg);
            setIsVerifying(false);
            setLoadingStatus("Logging in...");
            setIsLoading(false);
            toast.error(errorMsg);
        }
    }

    let riskLevel = "Low Risk"
    let riskColor = "text-green-800 dark:text-green-300"

    if (riskScore > 75) {
        riskLevel = "High Risk"
        riskColor = "text-red-800 dark:text-red-300"
    } else if (riskScore > 40) {
        riskLevel = "Medium Risk"
        riskColor = "text-yellow-800 dark:text-yellow-300"
    }

    return (
        <>
            <AlertDialogHeader className="font-montserrat">
                <AlertDialogTitle>Security Key Required</AlertDialogTitle>
                <AlertDialogDescription>
                    Please use your registered security key to complete login.
                </AlertDialogDescription>
                <div className="space-y-4 pt-4">
                    {riskScore > 0 && (
                        <div className="flex justify-between items-center">
                            <span className="text-sm font-medium">Login Risk:</span>
                            <span className={`text-xs px-2 py-1 rounded ${riskColor} bg-opacity-20`}>
                                {riskLevel} ({riskScore}/100)
                            </span>
                        </div>
                    )}

                    <div className="bg-yellow-50 dark:bg-transparent p-3 rounded-sm border border-yellow-400 dark:border-yellow-600">
                        <h4 className="text-yellow-800 dark:text-yellow-300 font-medium">Security Verification</h4>
                        <ul className="list-disc text-left pl-5 mt-1 text-sm text-yellow-700 dark:text-yellow-400 space-y-1">
                            <li>Ensure you're on the correct website</li>
                            <li>Your browser will prompt you to use your security key</li>
                            <li>Insert your key and tap the button when it flashes</li>
                            <li>Never share your security key with anyone</li>
                            {riskScore > 50 && (
                                <li className="text-red-700 dark:text-red-400 font-semibold">Additional verification required due to unusual activity</li>
                            )}
                        </ul>
                    </div>

                    <div className="flex justify-center">
                        <div className="animate-pulse text-6xl">🔑</div>
                    </div>

                    {securityKeyError && (
                        <div className="p-3 bg-red-50 dark:bg-transparent rounded-sm border border-red-400 dark:border-red-600 text-sm text-red-700 dark:text-red-400">
                            <p className="font-medium text-red-800 dark:text-red-300">Security Key Error</p>
                            <p>{securityKeyError}</p>
                        </div>
                    )}
                </div>
            </AlertDialogHeader>
            <AlertDialogFooter className="font-montserrat">
                <AlertDialogCancel onClick={onCancel}>Cancel</AlertDialogCancel>
                <AlertDialogAction
                    onClick={handleVerify}
                    disabled={isVerifying}
                    className="bg-primary text-primary-foreground hover:bg-primary/90"
                >
                    {isVerifying ? "Verifying..." : "Verify with Security Key"}
                </AlertDialogAction>
            </AlertDialogFooter>
        </>
    )
}

const InactiveKeyDialog = ({
                               open,
                               onClose
                           }: {
    open: boolean,
    onClose: () => void
}) => {
    return (
        <AlertDialog open={open} onOpenChange={onClose}>
            <AlertDialogContent className="w-[90%] max-w-md p-6">
                <AlertDialogHeader className="font-montserrat">
                    <div className="flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5 text-yellow-500" />
                        <AlertDialogTitle>Inactive Security Key</AlertDialogTitle>
                    </div>
                    <AlertDialogDescription>
                        Your security key is currently inactive and cannot be used for authentication.
                    </AlertDialogDescription>
                    <div className="space-y-4 pt-4">
                        <div className="bg-yellow-50 dark:bg-transparent p-3 rounded-sm border border-yellow-400 dark:border-yellow-600 text-sm">
                            <h4 className="text-yellow-800 dark:text-yellow-300 font-medium">What this means:</h4>
                            <p className="text-yellow-700 dark:text-yellow-400 mt-1">
                                Your security key has been registered but is currently disabled. This may be due to
                                administrative policy or the key was deactivated for security reasons.
                            </p>
                        </div>

                        <p className="text-sm">
                            Please contact your system administrator to activate your security key or try logging in with your password only.
                        </p>
                    </div>
                </AlertDialogHeader>
                <AlertDialogFooter className="font-montserrat">
                    <AlertDialogAction onClick={onClose} className="w-full">
                        OK, I Understand
                    </AlertDialogAction>
                </AlertDialogFooter>
            </AlertDialogContent>
        </AlertDialog>
    )
}

interface LoginFormProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export function LoginForm({ open, onOpenChange }: LoginFormProps) {
    const router = useRouter()

    const [showPassword, setShowPassword] = useState(false)
    const [username, setUsername] = useState("")
    const [password, setPassword] = useState("")
    const [isLoading, setIsLoading] = useState(false)
    const [loadingStatus, setLoadingStatus] = useState("Logging in...")

    const [securityKeyDialogOpen, setSecurityKeyDialogOpen] = useState(false)
    const [inactiveKeyDialogOpen, setInactiveKeyDialogOpen] = useState(false)
    const [authMethod, setAuthMethod] = useState<'password' | 'security_key'>('password')
    const [authToken, setAuthToken] = useState("")
    const [bindingNonce, setBindingNonce] = useState("")
    const [riskScore, setRiskScore] = useState(0)

    const [accountLocked, setAccountLocked] = useState(false)

    React.useEffect(() => {
        clearBindingData();
    }, []);

    interface LoginResponse {
        user_id: string;
        has_security_key: boolean;
        firstName: string;
        lastName: string;
        role: string;
        auth_token: string;
        binding_nonce: string;
        risk_score?: number;
    }

    interface WebAuthnResponse {
        publicKey: {
            challenge: string;
        };
        riskScore?: number;
    }

    interface ApiError {
        response?: {
            data?: {
                error?: string;
                accountLocked?: boolean;
                accountLockedUntil?: string;
                status?: string;
            };
        };
    }

    const redirectBasedOnRole = (role: string) => {
        if (role === 'admin') {
            router.push("/dashboard");
        } else {
            router.push("/chat");
        }
    }

    const handlePasswordLogin = async (e: React.FormEvent) => {
        e.preventDefault()

        if (!username || !password) {
            toast.error("Please enter all required fields")
            return
        }

        setIsLoading(true)
        setAuthMethod('password')

        try {
            const response = await axios.post<LoginResponse>(`${API_URL}/login`, {
                username,
                password
            })

            setIsLoading(false)

            if (!response.data.has_security_key) {
                toast.success("Login successful!")
                const userInfo = {
                    id: response.data.user_id,
                    username,
                    firstName: response.data.firstName,
                    lastName: response.data.lastName,
                    role: response.data.role,
                    hasSecurityKey: false,
                    authToken: response.data.auth_token,
                    securityKeyAuthenticated: false
                }
                sessionStorage.setItem('user', JSON.stringify(userInfo))
                initializeSecurityKeyStatus(false)
                onOpenChange(false);
                redirectBasedOnRole(response.data.role)
                return
            }

            toast.success("Login successful!")
            const userInfo = {
                id: response.data.user_id,
                username,
                firstName: response.data.firstName,
                lastName: response.data.lastName,
                role: response.data.role,
                hasSecurityKey: true,
                authToken: response.data.auth_token,
                securityKeyAuthenticated: false
            }
            sessionStorage.setItem('user', JSON.stringify(userInfo))
            initializeSecurityKeyStatus(false)
            onOpenChange(false);
            redirectBasedOnRole(response.data.role)

        } catch (err) {
            const apiError = err as ApiError;
            setIsLoading(false)

            if (apiError.response?.data?.accountLocked) {
                setAccountLocked(true)
                toast.error("Account locked due to too many failed attempts. Please contact your administrator.");
            } else {
                toast.error("Invalid credentials. Please try again.");
            }
        }
    }

    const handleSecurityKeyLogin = async () => {
        if (!username || !password) {
            toast.error("Please enter both your national ID/email and password")
            return
        }

        setIsLoading(true)
        setAuthMethod('security_key')

        try {
            const passwordResponse = await axios.post<LoginResponse>(`${API_URL}/login`, {
                username,
                password
            });

            setAuthToken(passwordResponse.data.auth_token || "");
            setBindingNonce(passwordResponse.data.binding_nonce || "");
            if (passwordResponse.data.risk_score !== undefined) {
                setRiskScore(passwordResponse.data.risk_score);
            }

            try {
                const authResponse = await axios.post<WebAuthnResponse>(`${API_URL}/webauthn/login/begin`, {
                    username,
                    secondFactor: true,
                    auth_token: passwordResponse.data.auth_token,
                    binding_nonce: passwordResponse.data.binding_nonce,
                    directSecurityKeyAuth: false
                })

                if (authResponse.data.riskScore !== undefined) {
                    setRiskScore(authResponse.data.riskScore)
                }

                sessionStorage.setItem('auth_token', passwordResponse.data.auth_token)
                sessionStorage.setItem('binding_nonce', passwordResponse.data.binding_nonce)

                setSecurityKeyDialogOpen(true)
            } catch (error) {
                const apiError = error as ApiError;
                console.error("WebAuthn begin error:", apiError);
                setIsLoading(false);

                if (apiError.response?.data?.status === 'inactive_key') {
                    setInactiveKeyDialogOpen(true);
                    return;
                }

                const errorMessage = "Unable to authenticate with security key. Please try again.";
                toast.error(errorMessage);
            }

        } catch (error) {
            const apiError = error as ApiError;
            setIsLoading(false)
            console.error("Login error:", error)

            if (apiError.response?.data?.accountLocked) {
                setAccountLocked(true)
                toast.error("Account locked due to too many failed attempts. Please contact your administrator.")
            } else {
                toast.error("Invalid credentials. Please try again.")
            }
        }
    }

    interface SecurityKeyUserData {
        user_id: string;
        firstName: string;
        lastName: string;
        role: string;
        auth_token: string;
    }

    const handleSecondFactorSuccess = (userData: SecurityKeyUserData) => {
        setSecurityKeyDialogOpen(false)
        setIsLoading(false)
        toast.success("Login successful with security key!")

        const userInfo = {
            id: userData.user_id,
            username,
            firstName: userData.firstName,
            lastName: userData.lastName,
            role: userData.role,
            hasSecurityKey: true,
            authToken: userData.auth_token,
            securityKeyAuthenticated: true
        }
        sessionStorage.setItem('user', JSON.stringify(userInfo))
        initializeSecurityKeyStatus(true)
        onOpenChange(false);
        redirectBasedOnRole(userData.role)
    }

    const handleSecondFactorCancel = () => {
        setSecurityKeyDialogOpen(false)
        clearBindingData()
        setAuthToken("")
        setBindingNonce("")
        setRiskScore(0)
        setIsLoading(false)
    }

    const handleInactiveKeyClose = () => {
        setInactiveKeyDialogOpen(false)
    }

    return (
        <>
            <Dialog open={open} onOpenChange={onOpenChange}>
                <DialogContent className="sm:max-w-[425px] font-montserrat">
                    <DialogHeader>
                        <DialogTitle>Welcome back</DialogTitle>
                        <DialogDescription>
                            Enter your credentials to sign in to your account
                        </DialogDescription>
                    </DialogHeader>
                    <form onSubmit={handlePasswordLogin} className="space-y-6">
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <Label htmlFor="username">National ID or Email</Label>
                                <Input
                                    id="username"
                                    placeholder="Enter your national ID or email"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    required/>
                            </div>
                            <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                    <Label htmlFor="password">Password</Label>
                                    <Link href="#"
                                          className="text-sm font-medium text-primary underline-offset-4 hover:underline">
                                        Forgot password?
                                    </Link>
                                </div>
                                <div className="relative">
                                    <Input
                                        id="password"
                                        type={showPassword ? "text" : "password"}
                                        placeholder="••••••••"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                    />
                                    <Button
                                        type="button"
                                        variant="ghost"
                                        size="icon"
                                        className="absolute right-0 top-0 h-full px-3 py-2 text-muted-foreground"
                                        onClick={() => setShowPassword(!showPassword)}
                                    >
                                        {showPassword ? <EyeOff className="h-4 w-4"/> : <Eye className="h-4 w-4"/>}
                                        <span
                                            className="sr-only">{showPassword ? "Hide password" : "Show password"}</span>
                                    </Button>
                                </div>
                            </div>
                        </div>

                        <Button className="w-full" type="submit" disabled={isLoading}>
                            {isLoading && authMethod === 'password' ? "Logging in..." : "Login"}
                        </Button>

                        <div className="flex items-center gap-3"><div className="w-full border-t border-zinc-200 dark:border-zinc-800"></div><span className="text-muted-foreground shrink-0 text-sm">or</span><div className="w-full border-t border-zinc-200 dark:border-zinc-800"></div></div>

                        <Button
                            type="button"
                            variant="outline"
                            className="w-full border-zinc-200 dark:border-zinc-800 text-primary bg-transparent hover:bg-primary/10"
                            onClick={handleSecurityKeyLogin}
                            disabled={isLoading}
                        >
                            {isLoading && authMethod === 'security_key' ? "Logging in..." : (
                                <>
                                    <Key className="h-4 w-4 mr-2"/>
                                    Login with Security Key
                                </>
                            )}
                        </Button>

                        {accountLocked && (
                            <div className="p-3 bg-red-50 dark:bg-transparent rounded-sm border border-red-400 dark:border-red-600 text-sm">
                                <p className="font-medium text-red-800 dark:text-red-300">Account Locked</p>
                                <p className="text-red-700 dark:text-red-400">
                                    For your security, this account has been locked due to multiple failed login attempts.
                                    Please contact your administrator to unlock your account.
                                </p>
                            </div>
                        )}
                    </form>
                </DialogContent>
            </Dialog>

            <AlertDialog open={securityKeyDialogOpen} onOpenChange={setSecurityKeyDialogOpen}>
                <AlertDialogContent className="w-[90%] max-w-md p-6">
                    <SecurityKeyPrompt
                        username={username}
                        authToken={authToken}
                        bindingNonce={bindingNonce}
                        riskScore={riskScore}
                        onSuccess={handleSecondFactorSuccess}
                        onCancel={handleSecondFactorCancel}
                        setLoadingStatus={setLoadingStatus}
                        setIsLoading={setIsLoading}
                    />
                </AlertDialogContent>
            </AlertDialog>

            <InactiveKeyDialog
                open={inactiveKeyDialogOpen}
                onClose={handleInactiveKeyClose}
            />
        </>
    )
}

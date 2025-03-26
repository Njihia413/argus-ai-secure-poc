"use client"

import React, { useState, useEffect } from "react"
import Link from "next/link"
import Image from "next/image"
import { useRouter } from "next/navigation"
import { Eye, EyeOff, ShieldCheck } from 'lucide-react'
import axios from "axios"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
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

import { authenticateWithSecurityKey, storeBindingData, clearBindingData } from "../utils/webauthn"
import { API_URL } from "../utils/constants"

// Security key verification component for second factor authentication
const SecurityKeyPrompt = ({
                               username,
                               authToken,
                               bindingNonce,
                               riskScore,
                               onSuccess,
                               onCancel,
                               setLoadingStatus
                           }: {
    username: string,
    authToken: string,
    bindingNonce: string,
    riskScore: number,
    onSuccess: (userData: any) => void,
    onCancel: () => void,
    setLoadingStatus: (status: string) => void
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
                    setSecurityKeyError(errorMessage)
                    setIsVerifying(false)
                    setLoadingStatus("Logging in...")
                }
            )
        } catch (err) {
            setSecurityKeyError("An unexpected error occurred")
            setIsVerifying(false)
            setLoadingStatus("Logging in...")
        }
    }

    // Risk level determination
    let riskLevel = "Low Risk"
    let riskColor = "text-green-800"

    if (riskScore > 75) {
        riskLevel = "High Risk"
        riskColor = "text-red-800"
    } else if (riskScore > 40) {
        riskLevel = "Medium Risk"
        riskColor = "text-yellow-800"
    }

    return (
        <>
            <AlertDialogHeader className="font-montserrat">
                <AlertDialogTitle>Security Key Required</AlertDialogTitle>
                <AlertDialogDescription className="space-y-4">
                    <p>
                        Your password has been verified. Please use your registered security key to complete login.
                    </p>

                    {riskScore > 0 && (
                        <div className="mt-3 flex justify-between items-center">
                            <span className="text-sm font-medium">Login Risk:</span>
                            <span className={`text-xs px-2 py-1 rounded ${riskColor} bg-opacity-20`}>
                                {riskLevel} ({riskScore}/100)
                            </span>
                        </div>
                    )}

                    <div className="bg-yellow-50 p-3 mt-3 rounded-sm border-l-4 border-yellow-400">
                        <h4 className="text-yellow-800 font-medium">Security Verification</h4>
                        <ul className="list-disc text-left pl-5 mt-1 text-sm text-yellow-700 space-y-1">
                            <li>Ensure you're on the correct website</li>
                            <li>Your browser will prompt you to use your security key</li>
                            <li>Insert your key and tap the button when it flashes</li>
                            <li>Never share your security key with anyone</li>
                            {riskScore > 50 && (
                                <li className="text-red-700 font-semibold">Additional verification required due to unusual activity</li>
                            )}
                        </ul>
                    </div>

                    <div className="flex justify-center">
                        <div className="animate-pulse text-6xl">🔑</div>
                    </div>

                    {securityKeyError && (
                        <div className="p-3 bg-red-50 border-l-4 border-red-500 text-sm text-red-700">
                            <p className="font-medium">Security Key Error</p>
                            <p>{securityKeyError}</p>
                        </div>
                    )}
                </AlertDialogDescription>
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

export default function LoginPage() {
    const router = useRouter()
    const [showPassword, setShowPassword] = useState(false)
    const [username, setUsername] = useState("")
    const [password, setPassword] = useState("")
    const [isLoading, setIsLoading] = useState(false)
    const [loadingStatus, setLoadingStatus] = useState("Logging in...")

    // States for second-factor authentication
    const [securityKeyDialogOpen, setSecurityKeyDialogOpen] = useState(false)
    const [authToken, setAuthToken] = useState("")
    const [bindingNonce, setBindingNonce] = useState("")
    const [riskScore, setRiskScore] = useState(0)

    // Account locked state
    const [accountLocked, setAccountLocked] = useState(false)
    const [accountLockedUntil, setAccountLockedUntil] = useState("")
    const [accountUnlockTimestamp, setAccountUnlockTimestamp] = useState<Date | null>(null)
    const [timeRemaining, setTimeRemaining] = useState("")

    // Countdown timer for account locked state
    useEffect(() => {
        // Only start countdown if account is locked and we have a timestamp
        if (accountLocked && accountUnlockTimestamp) {
            const countdownInterval = setInterval(() => {
                const now = new Date();
                const timeDiff = accountUnlockTimestamp.getTime() - now.getTime();

                if (timeDiff <= 0) {
                    // Account is now unlocked
                    setAccountLocked(false);
                    setTimeRemaining("");
                    clearInterval(countdownInterval);
                    toast.success("Account unlocked. You can now try logging in again.");
                } else {
                    // Calculate minutes and seconds
                    const minutes = Math.floor(timeDiff / (1000 * 60));
                    const seconds = Math.floor((timeDiff % (1000 * 60)) / 1000);
                    setTimeRemaining(`${minutes}:${seconds.toString().padStart(2, '0')}`);
                }
            }, 1000);

            // Clean up the interval when component unmounts or account becomes unlocked
            return () => clearInterval(countdownInterval);
        }
    }, [accountLocked, accountUnlockTimestamp]);

    // Clear any existing authentication data
    React.useEffect(() => {
        clearBindingData()
    }, [])

    // Handle standard password login
    const handlePasswordLogin = async (e: React.FormEvent) => {
        e.preventDefault()

        if (!username || !password) {
            toast.error("Please enter both username and password")
            return
        }

        setIsLoading(true)

        try {
            const response = await axios.post(`${API_URL}/login`, {
                username,
                password
            })

            setIsLoading(false)

            // Check if the user has a security key registered
            if (response.data.has_security_key) {
                // Keep loading state active during security key verification
                setIsLoading(true)
                // Store auth token and binding nonce for second factor
                if (response.data.auth_token && response.data.binding_nonce) {
                    setAuthToken(response.data.auth_token)
                    setBindingNonce(response.data.binding_nonce)
                    storeBindingData(response.data.auth_token, response.data.binding_nonce)
                }

                // Store risk score if provided
                if (response.data.risk_score !== undefined) {
                    setRiskScore(response.data.risk_score)
                }

                // Show appropriate message based on risk
                if (response.data.risk_score > 75) {
                    toast.warning("High risk login detected! Additional verification required.")
                } else if (response.data.risk_score > 40) {
                    toast.info("Unusual login detected. Please verify with your security key.")
                } else {
                    toast.info("Password verified. Please use your security key to complete login.")
                }

                // Open the security key dialog
                setSecurityKeyDialogOpen(true)
            } else {
                // If user doesn't have a security key registered
                toast.success("Login successful!")

                // Store user data in session storage
                const userInfo = {
                    id: response.data.user_id,
                    username,
                    firstName: response.data.firstName,
                    lastName: response.data.lastName,
                    hasSecurityKey: false,
                    authToken: response.data.auth_token
                }

                // Save to session storage
                sessionStorage.setItem('user', JSON.stringify(userInfo))

                // Navigate to chat
                router.push("/chat")
            }
        } catch (err: any) {
            setIsLoading(false)

            // Check for account locked message
            if (err.response?.data?.accountLocked ||
                (err.response?.data?.error && err.response.data.error.includes('Account is temporarily locked'))) {

                setAccountLocked(true)

                // If we have the ISO timestamp from the backend
                if (err.response?.data?.accountLockedUntil) {
                    setAccountUnlockTimestamp(new Date(err.response.data.accountLockedUntil))
                } else {
                    // Try to extract time from error message as fallback
                    const timeMatch = err.response?.data?.error?.match(/after (\d{2}:\d{2}:\d{2})/)
                    if (timeMatch && timeMatch[1]) {
                        setAccountLockedUntil(timeMatch[1])

                        // Create approximate timestamp based on HH:MM:SS
                        const [hours, minutes, seconds] = timeMatch[1].split(':').map(Number)
                        const unlockTime = new Date()
                        unlockTime.setHours(hours, minutes, seconds)
                        setAccountUnlockTimestamp(unlockTime)
                    }
                }

                toast.error("Account locked due to too many failed attempts")
            } else {
                toast.error(err.response?.data?.error || "Login failed")
            }
        }
    }

    // Handle successful second factor authentication
    const handleSecondFactorSuccess = (userData: any) => {
        setSecurityKeyDialogOpen(false)
        toast.success("Login successful! Both password and security key verified.")

        // Store user data in session storage
        const userInfo = {
            id: userData.user_id,
            username,
            firstName: userData.firstName,
            lastName: userData.lastName,
            hasSecurityKey: true,
            authToken: userData.auth_token
        }

        // Save to session storage
        sessionStorage.setItem('user', JSON.stringify(userInfo))

        // Navigate to chat
        router.push("/chat")
    }

    // Cancel second factor authentication
    const handleSecondFactorCancel = () => {
        setSecurityKeyDialogOpen(false)
        clearBindingData()
        setAuthToken("")
        setBindingNonce("")
        setRiskScore(0)
        setIsLoading(false)
    }

    return (
        <div className="grid min-h-screen grid-cols-1 lg:grid-cols-2">
            <div className="hidden bg-muted lg:block">
                <Image
                    src="/assets/images/Login.jpg"
                    alt="Login Image"
                    width={1920}
                    height={1080}
                    className="h-full w-full object-cover"
                    priority
                />
            </div>

            <div className="flex items-center justify-center font-montserrat px-4 py-10 sm:px-6 lg:px-8">
                <div className="mx-auto w-full max-w-sm space-y-8">
                    <div className="space-y-2 text-center">
                        <div className="flex justify-center">
                            <div className="rounded-full bg-primary/10 p-3">
                                <ShieldCheck className="h-8 w-8 text-primary" />
                            </div>
                        </div>
                        <h1 className="text-3xl font-bold">Welcome back</h1>
                        <p className="text-muted-foreground">Enter your credentials to sign in to your account</p>
                    </div>

                    <form onSubmit={handlePasswordLogin} className="space-y-6">
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <Label htmlFor="username">Username</Label>
                                <Input
                                    id="username"
                                    placeholder="Enter your username"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    required
                                />
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

                        {/* Standard Login Button */}
                        <Button className="w-full" type="submit" disabled={isLoading}>
                            {isLoading ? "Logging in..." : "Login"}
                        </Button>

                        {accountLocked && (
                            <div className="p-3 bg-red-50 border-l-4 border-red-500 text-sm">
                                <p className="font-medium text-red-800">Account Temporarily Locked</p>
                                <p className="text-red-700">
                                    For your security, this account has been temporarily locked due to multiple failed login attempts.
                                    {timeRemaining ? (
                                        <span className="font-bold"> Time remaining: {timeRemaining}</span>
                                    ) : (
                                        accountLockedUntil && <span> Please try again after {accountLockedUntil}.</span>
                                    )}
                                </p>
                            </div>
                        )}

                        <div className="text-center text-sm">
                            Don't have an account?{" "}
                            <Link href="/signup" className="font-medium text-primary underline-offset-4 hover:underline">
                                Create one
                            </Link>
                        </div>
                    </form>
                </div>
            </div>

            {/* Security Key Alert Dialog with improved padding for small screens */}
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
                    />
                </AlertDialogContent>
            </AlertDialog>
        </div>
    )
}

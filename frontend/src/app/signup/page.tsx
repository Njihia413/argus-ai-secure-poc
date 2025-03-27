"use client"

import React, { useState } from "react"
import Link from "next/link"
import Image from "next/image"
import { ShieldCheck, Eye, EyeOff } from "lucide-react"
import { toast } from "sonner"
import axios from "axios"
import { useRouter } from "next/navigation"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {API_URL} from "@/app/utils/constants";

export default function SignupPage() {
    const router = useRouter()
    const [showPassword, setShowPassword] = useState(false)
    const [showConfirmPassword, setShowConfirmPassword] = useState(false)

    // Form state
    const [firstName, setFirstName] = useState("")
    const [lastName, setLastName] = useState("")
    const [username, setUsername] = useState("")
    const [password, setPassword] = useState("")
    const [confirmPassword, setConfirmPassword] = useState("")

    // Loading state
    const [isLoading, setIsLoading] = useState(false)

    const handleSignup = async (e: React.FormEvent) => {
        e.preventDefault()

        // Form validation
        if (!firstName || !lastName || !username || !password) {
            toast.error("All fields are required")
            return
        }

        if (password !== confirmPassword) {
            toast.error("Passwords do not match")
            return
        }

        setIsLoading(true)

        try {
            const response = await axios.post(`${API_URL}/register`, {
                firstName,
                lastName,
                username,
                password
            })

            toast.success("Account created successfully!")

            // Redirect to login page after successful registration
            setTimeout(() => {
                router.push("/login")
            }, 1500)

        } catch (err: any) {
            const errorMessage = err.response?.data?.error || "Registration failed"
            toast.error(errorMessage)
        } finally {
            setIsLoading(false)
        }
    }

    const handleResetDb = async () => {
        if (window.confirm('Are you sure you want to reset the database? All user data will be lost.')) {
            try {
                const response = await axios.post(`${API_URL}/reset-db`);
                toast.success(response.data.message || 'Database reset successfully');
            } catch (err) {
                toast.error('Failed to reset database');
                console.error('Reset database error:', err);
            }
        }
    };

    return (
        <div className="grid min-h-screen grid-cols-1 lg:grid-cols-2">
            <div className="hidden bg-muted lg:block">
                <Image
                    src="/assets/images/Signup.jpeg"
                    alt="Signup Image"
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
                                <ShieldCheck className="h-8 w-8 text-primary"/>
                            </div>
                        </div>
                        <h1 className="text-3xl font-bold">Create an account</h1>
                        <p className="text-muted-foreground">Enter your information to get started</p>
                    </div>

                    <form onSubmit={handleSignup} className="space-y-6">
                        <div className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <Label htmlFor="firstName">First Name</Label>
                                    <Input
                                        id="firstName"
                                        placeholder="Eg John"
                                        value={firstName}
                                        onChange={(e) => setFirstName(e.target.value)}
                                        required
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="lastName">Last Name</Label>
                                    <Input
                                        id="lastName"
                                        placeholder="Eg Doe"
                                        value={lastName}
                                        onChange={(e) => setLastName(e.target.value)}
                                        required
                                    />
                                </div>
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="username">Username</Label>
                                <Input
                                    id="username"
                                    placeholder="Eg johndoe"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    required
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="password">Password</Label>
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

                            <div className="space-y-2">
                                <Label htmlFor="confirmPassword">Confirm password</Label>
                                <div className="relative">
                                    <Input
                                        id="confirmPassword"
                                        type={showConfirmPassword ? "text" : "password"}
                                        placeholder="••••••••"
                                        value={confirmPassword}
                                        onChange={(e) => setConfirmPassword(e.target.value)}
                                        required
                                    />
                                    <Button
                                        type="button"
                                        variant="ghost"
                                        size="icon"
                                        className="absolute right-0 top-0 h-full px-3 py-2 text-muted-foreground"
                                        onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                    >
                                        {showConfirmPassword ? <EyeOff className="h-4 w-4"/> :
                                            <Eye className="h-4 w-4"/>}
                                        <span
                                            className="sr-only">{showConfirmPassword ? "Hide password" : "Show password"}</span>
                                    </Button>
                                </div>
                            </div>
                        </div>

                        <Button className="w-full" type="submit" disabled={isLoading}>
                            {isLoading ? "Creating account..." : "Create account"}
                        </Button>

                        <div className="text-center text-sm">
                            Already have an account?{" "}
                            <Link href="/login" className="font-medium text-primary underline-offset-4 hover:underline">
                                Log in
                            </Link>
                        </div>
                    </form>

                    {/*<div className="mt-8 pt-4 border-t border-gray-300">*/}
                    {/*    /!*<p className="text-xs text-gray-500 mb-2">Admin Functions (Development Only)</p>*!/*/}
                    {/*    <Button*/}
                    {/*        onClick={handleResetDb}*/}
                    {/*        className="w-full bg-red-500 text-white font-bold py-2 px-4 rounded hover:bg-red-600 focus:outline-none focus:ring-2 focus:ring-red-300 transition-colors"*/}
                    {/*    >*/}
                    {/*        Reset Database*/}
                    {/*    </Button>*/}
                    {/*    /!*<p className="text-xs text-gray-500 mt-1">Warning: This will delete all user data</p>*!/*/}
                    {/*</div>*/}
                </div>
            </div>
        </div>
    )
}

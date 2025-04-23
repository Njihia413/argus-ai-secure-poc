"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { UserPlus, MoreHorizontal } from "lucide-react"
import axios from "axios"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"

// Sample data for the users table
const recentUsersData = [
  {
    id: 1,
    name: "Alex Johnson",
    username: "alex_j",
    email: "alex@example.com",
    role: "Developer",
    hasSecurityKey: true,
    lastLogin: "2 minutes ago",
    status: "Online",
  },
  {
    id: 2,
    name: "Sarah Wilson",
    username: "sarah_w",

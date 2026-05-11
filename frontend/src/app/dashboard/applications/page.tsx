"use client";

import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  AppWindow,
  Check,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import { API_URL } from "@/app/utils/constants";

interface RegisteredApp {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  api_key_prefix: string;
  callback_url: string | null;
  is_active: boolean;
  created_at: string | null;
  created_by: string | null;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={copy}
      className="ml-2 p-1 rounded hover:bg-zinc-100 dark:hover:bg-zinc-800 text-muted-foreground"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

export default function ApplicationsPage() {
  const router = useRouter();
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [apps, setApps] = useState<RegisteredApp[]>([]);
  const [loading, setLoading] = useState(true);
  const [notAdmin, setNotAdmin] = useState(false);

  // Register dialog
  const [registerOpen, setRegisterOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newCallbackUrl, setNewCallbackUrl] = useState("");
  const [registering, setRegistering] = useState(false);

  // Edit dialog
  const [editApp, setEditApp] = useState<RegisteredApp | null>(null);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editCallbackUrl, setEditCallbackUrl] = useState("");
  const [editActive, setEditActive] = useState(true);
  const [saving, setSaving] = useState(false);

  // Delete dialog
  const [deleteApp, setDeleteApp] = useState<RegisteredApp | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Regenerate key dialog
  const [regenApp, setRegenApp] = useState<RegisteredApp | null>(null);
  const [regenerating, setRegenerating] = useState(false);

  // API key reveal dialog
  const [revealedKey, setRevealedKey] = useState<{ key: string; name: string } | null>(null);
  const [keyVisible, setKeyVisible] = useState(false);

  useEffect(() => {
    const stored = sessionStorage.getItem("user");
    const user = stored ? JSON.parse(stored) : null;
    if (!user?.authToken) {
      router.push("/");
      return;
    }
    if (user.role !== "admin") {
      setNotAdmin(true);
      setLoading(false);
      return;
    }
    setAuthToken(user.authToken);
  }, [router]);

  const fetchApps = async (token: string) => {
    const res = await axios.get<{ apps: RegisteredApp[] }>(
      `${API_URL}/admin/registered-apps`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    return res.data.apps;
  };

  useEffect(() => {
    if (!authToken) return;
    (async () => {
      try {
        setApps(await fetchApps(authToken));
      } catch {
        toast.error("Could not load registered applications.");
      } finally {
        setLoading(false);
      }
    })();
  }, [authToken]);

  const register = async () => {
    if (!newName.trim() || !authToken) return;
    setRegistering(true);
    try {
      const res = await axios.post<RegisteredApp & { api_key?: string }>(
        `${API_URL}/admin/registered-apps`,
        {
          name: newName.trim(),
          description: newDesc.trim() || undefined,
          callback_url: newCallbackUrl.trim() || undefined,
        },
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      const created = res.data;
      setApps(await fetchApps(authToken));
      setRegisterOpen(false);
      setNewName("");
      setNewDesc("");
      setNewCallbackUrl("");
      if (created.api_key) {
        setRevealedKey({ key: created.api_key, name: created.name });
        setKeyVisible(false);
      }
      toast.success(`"${created.name}" registered.`);
    } catch (err) {
      const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
      toast.error(data?.error || "Failed to register application.");
    } finally {
      setRegistering(false);
    }
  };

  const openEdit = (app: RegisteredApp) => {
    setEditApp(app);
    setEditName(app.name);
    setEditDesc(app.description ?? "");
    setEditCallbackUrl(app.callback_url ?? "");
    setEditActive(app.is_active);
  };

  const saveEdit = async () => {
    if (!editApp || !authToken) return;
    setSaving(true);
    try {
      await axios.patch(
        `${API_URL}/admin/registered-apps/${editApp.id}`,
        {
          name: editName.trim(),
          description: editDesc.trim() || null,
          callback_url: editCallbackUrl.trim() || null,
          is_active: editActive,
        },
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      setApps(await fetchApps(authToken));
      setEditApp(null);
      toast.success("Changes saved.");
    } catch {
      toast.error("Failed to save changes.");
    } finally {
      setSaving(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteApp || !authToken) return;
    setDeleting(true);
    try {
      await axios.delete(`${API_URL}/admin/registered-apps/${deleteApp.id}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      setApps(await fetchApps(authToken));
      setDeleteApp(null);
      toast.success(`"${deleteApp.name}" removed.`);
    } catch {
      toast.error("Failed to delete application.");
    } finally {
      setDeleting(false);
    }
  };

  const regenerateKey = async () => {
    if (!regenApp || !authToken) return;
    setRegenerating(true);
    try {
      const res = await axios.post<RegisteredApp & { api_key?: string }>(
        `${API_URL}/admin/registered-apps/${regenApp.id}/regenerate-key`,
        {},
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      setApps(await fetchApps(authToken));
      setRegenApp(null);
      if (res.data.api_key) {
        setRevealedKey({ key: res.data.api_key, name: res.data.name });
        setKeyVisible(false);
      }
      toast.success("API key regenerated.");
    } catch {
      toast.error("Failed to regenerate API key.");
    } finally {
      setRegenerating(false);
    }
  };

  if (notAdmin) {
    return (
      <div className="p-6 font-montserrat max-w-xl">
        <Card>
          <CardHeader>
            <CardTitle>Admins only</CardTitle>
            <CardDescription>
              Application registration is restricted to administrators.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 font-montserrat">
      <div className="mb-8 flex items-start gap-3">
        <div className="p-2 rounded-lg bg-primary/10 text-primary">
          <AppWindow className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">Registered Applications</h1>
          <p className="text-sm text-muted-foreground max-w-3xl mt-1">
            External applications (such as chat clients) register here to receive an API key.
            They use it to verify user sessions and retrieve role-based access information.
          </p>
        </div>
      </div>

      <div className="flex justify-end mb-4">
        <Button onClick={() => setRegisterOpen(true)}>
          <Plus className="h-4 w-4" />
          Register App
        </Button>
      </div>

      {loading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Loading…
          </CardContent>
        </Card>
      ) : apps.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No applications registered yet. Click <strong>Register App</strong> to add one.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {apps.map((app) => (
            <Card key={app.id}>
              <CardContent className="py-4">
                <div className="flex items-start gap-4">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
                    <AppWindow className="h-4 w-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium">{app.name}</span>
                      <Badge variant={app.is_active ? "default" : "secondary"}>
                        {app.is_active ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                    {app.description && (
                      <p className="text-sm text-muted-foreground mt-0.5">{app.description}</p>
                    )}
                    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                      <span>
                        <span className="font-medium text-foreground">slug: </span>
                        <span className="font-mono">{app.slug}</span>
                      </span>
                      <span>
                        <span className="font-medium text-foreground">key: </span>
                        <span className="font-mono">{app.api_key_prefix}…</span>
                      </span>
                      {app.callback_url && (
                        <span>
                          <span className="font-medium text-foreground">callback: </span>
                          <span className="font-mono truncate max-w-[200px] inline-block align-bottom">{app.callback_url}</span>
                        </span>
                      )}
                      {app.created_at && (
                        <span>
                          Added {new Date(app.created_at).toLocaleDateString()}
                          {app.created_by ? ` by ${app.created_by}` : ""}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      title="Edit"
                      onClick={() => openEdit(app)}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      title="Regenerate API key"
                      onClick={() => setRegenApp(app)}
                    >
                      <RefreshCw className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-destructive hover:text-destructive"
                      title="Delete"
                      onClick={() => setDeleteApp(app)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Register dialog */}
      <Dialog
        open={registerOpen}
        onOpenChange={(open) => {
          setRegisterOpen(open);
          if (!open) { setNewName(""); setNewDesc(""); setNewCallbackUrl(""); }
        }}
      >
        <DialogContent className="sm:max-w-[440px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Register Application</DialogTitle>
            <DialogDescription>
              An API key will be generated. Store it securely — it is only shown once.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="appName">Name <span className="text-destructive">*</span></Label>
              <Input
                id="appName"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. Nexus AI Chat"
                onKeyDown={(e) => e.key === "Enter" && register()}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="appDesc">Description</Label>
              <Textarea
                id="appDesc"
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                placeholder="Short description of what this app does…"
                rows={2}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="callbackUrl">Callback URL</Label>
              <Input
                id="callbackUrl"
                value={newCallbackUrl}
                onChange={(e) => setNewCallbackUrl(e.target.value)}
                placeholder="https://your-app.example.com/callback"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRegisterOpen(false)}>Cancel</Button>
            <Button onClick={register} disabled={registering || !newName.trim()}>
              {registering ? "Registering…" : "Register"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={!!editApp} onOpenChange={(open) => !open && setEditApp(null)}>
        <DialogContent className="sm:max-w-[440px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Edit Application</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="editName">Name</Label>
              <Input
                id="editName"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="editDesc">Description</Label>
              <Textarea
                id="editDesc"
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                rows={2}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="editCallbackUrl">Callback URL</Label>
              <Input
                id="editCallbackUrl"
                value={editCallbackUrl}
                onChange={(e) => setEditCallbackUrl(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="editActive"
                checked={editActive}
                onChange={(e) => setEditActive(e.target.checked)}
                className="h-4 w-4 rounded"
              />
              <Label htmlFor="editActive">Active</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditApp(null)}>Cancel</Button>
            <Button onClick={saveEdit} disabled={saving || !editName.trim()}>
              {saving ? "Saving…" : "Save changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Regenerate key confirm dialog */}
      <Dialog open={!!regenApp} onOpenChange={(open) => !open && setRegenApp(null)}>
        <DialogContent className="sm:max-w-[400px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Regenerate API Key</DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <p className="text-sm">
              Regenerate the API key for <strong>{regenApp?.name}</strong>? The existing key will
              stop working immediately. The new key is shown once.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRegenApp(null)}>Cancel</Button>
            <Button variant="destructive" disabled={regenerating} onClick={regenerateKey}>
              {regenerating ? "Regenerating…" : "Regenerate"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm dialog */}
      <Dialog open={!!deleteApp} onOpenChange={(open) => !open && setDeleteApp(null)}>
        <DialogContent className="sm:max-w-[400px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Delete Application</DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <p className="text-sm">
              Permanently delete <strong>{deleteApp?.name}</strong>? Its API key will stop working
              immediately and this cannot be undone.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteApp(null)}>Cancel</Button>
            <Button variant="destructive" disabled={deleting} onClick={confirmDelete}>
              {deleting ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* API key one-time display dialog */}
      <Dialog open={!!revealedKey} onOpenChange={(open) => !open && setRevealedKey(null)}>
        <DialogContent className="sm:max-w-[480px] font-montserrat">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-primary" />
              API Key for {revealedKey?.name}
            </DialogTitle>
            <DialogDescription>
              Copy this key now. It will not be shown again.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="flex items-center rounded-lg border bg-muted px-3 py-2.5 font-mono text-sm break-all">
              <span className={keyVisible ? "" : "select-none blur-sm"}>
                {revealedKey?.key}
              </span>
              <div className="ml-auto flex items-center gap-1 pl-2 shrink-0">
                <button
                  onClick={() => setKeyVisible(!keyVisible)}
                  className="p-1 rounded hover:bg-background text-muted-foreground"
                >
                  {keyVisible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </button>
                {revealedKey && <CopyButton text={revealedKey.key} />}
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Pass this as <code className="font-mono bg-muted px-1 rounded">api_key</code> in calls
              to <code className="font-mono bg-muted px-1 rounded">POST /api/app-auth/verify</code>.
            </p>
          </div>
          <DialogFooter>
            <Button onClick={() => setRevealedKey(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

"use client";

import { useEffect, useMemo, useState } from "react";
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
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { AppWindow, Plus, Shield, Trash2 } from "lucide-react";
import { API_URL } from "@/app/utils/constants";
import { Tier, TierPill } from "@/app/utils/tiers";
import { ADMIN_NAV_SECTIONS } from "@/app/utils/admin-nav";

interface AIModel {
  id: number;
  slug: string;
  display_name: string;
  min_tier: Tier;
  is_active: boolean;
}

interface RegisteredApp {
  id: number;
  slug: string;
  name: string;
  is_active: boolean;
}

interface RolePermissions {
  role: string;
  models: string[];
  apps: string[];
  admin_sections: string[];
  registered_apps: string[];
}

interface RoleSummary {
  role: string;
  display_name: string;
  is_system: boolean;
  counts: Record<string, number>;
}


function slugPreview(name: string): string {
  return name
    .toLowerCase()
    .replace(/[\s-]+/g, "_")
    .replace(/[^a-z0-9_]/g, "")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .slice(0, 32);
}

export default function RolesPage() {
  const router = useRouter();
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [roles, setRoles] = useState<RoleSummary[]>([]);
  const [selectedRole, setSelectedRole] = useState<string>("");
  const [models, setModels] = useState<AIModel[]>([]);
  const [registeredApps, setRegisteredApps] = useState<RegisteredApp[]>([]);
  const [perms, setPerms] = useState<RolePermissions | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
const [notAdmin, setNotAdmin] = useState(false);

  // Create role dialog
  const [createRoleOpen, setCreateRoleOpen] = useState(false);
  const [newRoleDisplayName, setNewRoleDisplayName] = useState("");
  const [creating, setCreating] = useState(false);

  // Delete role dialog
  const [deleteConfirmRole, setDeleteConfirmRole] = useState<RoleSummary | null>(null);
  const [deleting, setDeleting] = useState(false);

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

  const fetchRoles = async (token: string) => {
    const res = await axios.get<{ roles: RoleSummary[] }>(`${API_URL}/admin/roles`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return res.data.roles;
  };

  useEffect(() => {
    if (!authToken) return;
    const headers = { Authorization: `Bearer ${authToken}` };
    (async () => {
      try {
        const [m, r, a] = await Promise.all([
          axios.get<{ models: AIModel[] }>(`${API_URL}/admin/ai-models`, { headers }),
          axios.get<{ roles: RoleSummary[] }>(`${API_URL}/admin/roles`, { headers }),
          axios.get<{ apps: RegisteredApp[] }>(`${API_URL}/admin/registered-apps`, { headers }),
        ]);
        setModels(m.data.models);
        setRoles(r.data.roles);
        setRegisteredApps(a.data.apps.filter((a) => a.is_active));
        if (r.data.roles.length > 0) {
          setSelectedRole(r.data.roles[0].role);
        }
      } catch (err) {
        const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
        toast.error(data?.error || "Could not load catalog.");
      }
    })();
  }, [authToken]);

  useEffect(() => {
    if (!authToken || !selectedRole) return;
    setLoading(true);
    axios
      .get<RolePermissions>(`${API_URL}/admin/roles/${selectedRole}/permissions`, {
        headers: { Authorization: `Bearer ${authToken}` },
      })
      .then((res) => {
        setPerms(res.data);
        setLoading(false);
      })
      .catch((err) => {
        const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
        toast.error(data?.error || "Could not load role permissions.");
        setLoading(false);
      });
  }, [authToken, selectedRole]);

  const activeModels = useMemo(() => models.filter((m) => m.is_active), [models]);

  const toggle = (bucket: keyof Omit<RolePermissions, "role">, slug: string) => {
    if (!perms) return;
    const current = new Set(perms[bucket]);
    if (current.has(slug)) current.delete(slug);
    else current.add(slug);
    setPerms({ ...perms, [bucket]: Array.from(current) });
  };

  const save = async () => {
    if (!perms || !authToken) return;
    setSaving(true);
    try {
      await axios.put(
        `${API_URL}/admin/roles/${selectedRole}/permissions`,
        {
          models: perms.models,
          apps: perms.apps,
          admin_sections: perms.admin_sections,
          registered_apps: perms.registered_apps,
        },
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      toast.success(`Permissions saved for ${selectedRole}.`);
      if (selectedRole === "admin") {
        window.dispatchEvent(new CustomEvent("argus-sections-changed"));
      }
    } catch {
      toast.error("Failed to save permissions.");
    } finally {
      setSaving(false);
    }
  };

  const createRole = async () => {
    if (!newRoleDisplayName.trim() || !authToken) return;
    setCreating(true);
    try {
      await axios.post(
        `${API_URL}/admin/roles`,
        { display_name: newRoleDisplayName.trim() },
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      toast.success(`Role "${newRoleDisplayName}" created.`);
      setCreateRoleOpen(false);
      const prevRoles = roles;
      const refreshed = await fetchRoles(authToken);
      setRoles(refreshed);
      setNewRoleDisplayName("");
      // Auto-select the newly created role
      const newRole = refreshed.find((r) => !prevRoles.some((old) => old.role === r.role));
      if (newRole) setSelectedRole(newRole.role);
    } catch (err) {
      const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
      toast.error(data?.error || "Failed to create role.");
    } finally {
      setCreating(false);
    }
  };

  const deleteRole = async (r: RoleSummary) => {
    if (!authToken) return;
    setDeleting(true);
    try {
      await axios.delete(`${API_URL}/admin/roles/${r.role}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      toast.success(`Role "${r.display_name}" deleted.`);
      setDeleteConfirmRole(null);
      const refreshed = await fetchRoles(authToken);
      setRoles(refreshed);
      if (selectedRole === r.role && refreshed.length > 0) {
        setSelectedRole(refreshed[0].role);
      }
    } catch (err) {
      const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
      toast.error(data?.error || "Failed to delete role.");
    } finally {
      setDeleting(false);
    }
  };

  if (notAdmin) {
    return (
      <div className="p-6 font-montserrat max-w-xl">
        <Card>
          <CardHeader>
            <CardTitle>Admins only</CardTitle>
            <CardDescription>
              Role and permission configuration is restricted to administrators.
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
          <Shield className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">Roles &amp; Permissions</h1>
          <p className="text-sm text-muted-foreground max-w-3xl mt-1">
            Each user&apos;s access is the intersection of two things: <strong>their login tier</strong>{" "}
            (how strongly they authenticated) and <strong>their role permissions</strong> (set here).
            Both must allow a resource for the user to reach it.
          </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        {/* Role picker */}
        <div className="space-y-2">
          <div className="flex items-center justify-between px-1 mb-1">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Roles
            </p>
            <Button
              size="sm"
              className="h-7 px-2 text-xs"
              onClick={() => setCreateRoleOpen(true)}
            >
              <Plus className="h-3 w-3" /> New
            </Button>
          </div>
          <div className="mt-3" />
          {roles.map((r) => {
            const active = selectedRole === r.role;
            return (
              <button
                key={r.role}
                onClick={() => setSelectedRole(r.role)}
                className={`w-full text-left p-3 rounded-xl border transition-colors ${
                  active
                    ? "border-primary bg-primary/5"
                    : "border-zinc-200 dark:border-zinc-800 hover:bg-muted/50"
                }`}
              >
                <div className="text-sm font-medium">{r.display_name}</div>
              </button>
            );
          })}
        </div>

        {/* Editor */}
        <div className="space-y-6">
          {loading || !perms ? (
            <Card>
              <CardContent className="py-12 text-center text-sm text-muted-foreground">
                Loading permissions…
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-semibold">
                    {roles.find((r) => r.role === selectedRole)?.display_name}
                  </h2>
                  <p className="text-xs text-muted-foreground">
                    Tick the items members of this role are permitted to use.
                  </p>
                </div>
                <Button onClick={save} disabled={saving}>
                  {saving ? "Saving…" : "Save changes"}
                </Button>
              </div>

              {selectedRole !== "admin" && (
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-base">AI Models</CardTitle>
                        <CardDescription className="mt-1">
                          Which Groq models members of this role can chat with. The badge shows the
                          minimum login tier the user also needs.
                        </CardDescription>
                      </div>
                      <Badge variant="outline" className="ml-4">
                        {perms.models.filter((slug) => activeModels.some((m) => m.slug === slug)).length} / {activeModels.length} allowed
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                      {activeModels.map((m) => (
                        <label
                          key={m.slug}
                          className="flex items-center gap-3 py-3 cursor-pointer"
                        >
                          <Checkbox
                            checked={perms.models.includes(m.slug)}
                            onCheckedChange={() => toggle("models", m.slug)}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium">{m.display_name}</div>
                            <div className="text-xs text-muted-foreground font-mono truncate">
                              {m.slug}
                            </div>
                          </div>
                          <TierPill tier={m.min_tier} />
                        </label>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {selectedRole !== "admin" && registeredApps.length > 0 && (
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-base">Registered Applications</CardTitle>
                        <CardDescription className="mt-1">
                          Which external applications members of this role are permitted to access
                          via the app-auth API.
                        </CardDescription>
                      </div>
                      <Badge variant="outline" className="ml-4">
                        {perms.registered_apps.filter((slug) => registeredApps.some((a) => a.slug === slug)).length} / {registeredApps.length} allowed
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                      {registeredApps.map((a) => (
                        <label
                          key={a.slug}
                          className="flex items-center gap-3 py-3 cursor-pointer"
                        >
                          <Checkbox
                            checked={perms.registered_apps.includes(a.slug)}
                            onCheckedChange={() => toggle("registered_apps", a.slug)}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <AppWindow className="h-4 w-4 text-muted-foreground shrink-0" />
                              <span className="text-sm font-medium">{a.name}</span>
                            </div>
                            <div className="text-xs text-muted-foreground font-mono truncate">
                              {a.slug}
                            </div>
                          </div>
                        </label>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {selectedRole === "admin" && (
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-base">Admin panel access</CardTitle>
                        <CardDescription className="mt-1">
                          Which admin areas administrators may enter.
                        </CardDescription>
                      </div>
                      <Badge variant="outline" className="ml-4">
                        {perms.admin_sections.length} / {ADMIN_NAV_SECTIONS.length} allowed
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                      {ADMIN_NAV_SECTIONS.map((s) => (
                        <label
                          key={s.slug}
                          className="flex items-center gap-3 py-3 cursor-pointer"
                        >
                          <Checkbox
                            checked={perms.admin_sections.includes(s.slug)}
                            onCheckedChange={() => toggle("admin_sections", s.slug)}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{s.label}</span>
                              {s.elevated && (
                                <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-4 font-medium text-amber-600 dark:text-amber-400 bg-amber-100 dark:bg-amber-950/50 border-0">
                                  Key required
                                </Badge>
                              )}
                            </div>
                            <div className="text-xs text-muted-foreground font-mono">{s.slug}</div>
                          </div>
                        </label>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {!roles.find((r) => r.role === selectedRole)?.is_system && (
                <Card className="border-destructive/40">
                  <CardHeader>
                    <CardTitle className="text-base text-destructive">Delete role</CardTitle>
                    <CardDescription>
                      Permanently remove <strong>{roles.find((r) => r.role === selectedRole)?.display_name}</strong> and all its permissions. This cannot be undone. Users currently assigned this role must be reassigned before deletion.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Button
                      variant="destructive"
                      onClick={() => {
                        const r = roles.find((x) => x.role === selectedRole);
                        if (r) setDeleteConfirmRole(r);
                      }}
                    >
                      <Trash2 className="h-4 w-4 mr-1.5" />
                      Delete {roles.find((r) => r.role === selectedRole)?.display_name}
                    </Button>
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </div>
      </div>

      {/* Create Role dialog */}
      <Dialog open={createRoleOpen} onOpenChange={(open) => { setCreateRoleOpen(open); if (!open) setNewRoleDisplayName(""); }}>
        <DialogContent className="sm:max-w-[400px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Create Role</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="roleDisplayName">Role Name</Label>
              <Input
                id="roleDisplayName"
                value={newRoleDisplayName}
                onChange={(e) => setNewRoleDisplayName(e.target.value)}
                placeholder="e.g. Finance, Legal, HR, Marketing..."
                onKeyDown={(e) => e.key === "Enter" && createRole()}
              />
              {newRoleDisplayName && (
                <p className="text-xs text-muted-foreground font-mono">
                  slug: {slugPreview(newRoleDisplayName)}
                </p>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateRoleOpen(false)}>Cancel</Button>
            <Button onClick={createRole} disabled={creating || !newRoleDisplayName.trim()}>
              {creating ? "Creating…" : "Create Role"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm dialog */}
      <Dialog open={!!deleteConfirmRole} onOpenChange={(open) => !open && setDeleteConfirmRole(null)}>
        <DialogContent className="sm:max-w-[400px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Delete Role</DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <p className="text-sm">
              Delete <strong>{deleteConfirmRole?.display_name}</strong>? This removes all permissions
              assigned to this role and cannot be undone.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteConfirmRole(null)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={deleting}
              onClick={() => deleteConfirmRole && deleteRole(deleteConfirmRole)}
            >
              {deleting ? "Deleting…" : "Delete Role"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

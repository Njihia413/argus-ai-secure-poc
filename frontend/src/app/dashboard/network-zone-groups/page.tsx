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
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AppWindow, Layers, Network, Pencil, Plus, Trash2, X } from "lucide-react";
import { API_URL } from "@/app/utils/constants";

interface NetworkZoneGroup {
  id: number;
  name: string;
  description: string | null;
  is_active: boolean;
  created_at: string | null;
  zones: { id: number; name: string; is_active: boolean }[];
  apps: { id: number; name: string; slug: string; is_active: boolean }[];
}

interface NetworkZone {
  id: number;
  name: string;
  is_active: boolean;
}

interface RegisteredApp {
  id: number;
  name: string;
  slug: string;
  is_active: boolean;
}

const emptyForm = { name: "", description: "", is_active: true };

export default function NetworkZoneGroupsPage() {
  const router = useRouter();
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [groups, setGroups] = useState<NetworkZoneGroup[]>([]);
  const [allZones, setAllZones] = useState<NetworkZone[]>([]);
  const [allApps, setAllApps] = useState<RegisteredApp[]>([]);
  const [loading, setLoading] = useState(true);

  // Create / edit dialog
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<NetworkZoneGroup | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [saving, setSaving] = useState(false);

  // Delete dialog
  const [deleteTarget, setDeleteTarget] = useState<NetworkZoneGroup | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Per-group add selectors (keyed by group id)
  const [addZoneId, setAddZoneId] = useState<Record<number, string>>({});
  const [addAppId, setAddAppId] = useState<Record<number, string>>({});

  useEffect(() => {
    const stored = sessionStorage.getItem("user");
    const user = stored ? JSON.parse(stored) : null;
    if (!user?.authToken) { router.push("/"); return; }
    setAuthToken(user.authToken);
  }, [router]);

  useEffect(() => {
    if (!authToken) return;
    (async () => {
      try {
        const [groupsRes, zonesRes, appsRes] = await Promise.all([
          axios.get<{ network_zone_groups: NetworkZoneGroup[] }>(`${API_URL}/admin/network-zone-groups?all=true`, {
            headers: { Authorization: `Bearer ${authToken}` },
          }),
          axios.get<{ zones: NetworkZone[] }>(`${API_URL}/admin/network-zones?all=true`, {
            headers: { Authorization: `Bearer ${authToken}` },
          }),
          axios.get<{ apps: RegisteredApp[] }>(`${API_URL}/admin/registered-apps?all=true`, {
            headers: { Authorization: `Bearer ${authToken}` },
          }),
        ]);
        setGroups(groupsRes.data.network_zone_groups);
        setAllZones(zonesRes.data.zones);
        setAllApps(appsRes.data.apps);
      } catch {
        toast.error("Could not load zone groups.");
      } finally {
        setLoading(false);
      }
    })();
  }, [authToken]);

  const fetchGroups = async () => {
    if (!authToken) return;
    try {
      const res = await axios.get<{ network_zone_groups: NetworkZoneGroup[] }>(
        `${API_URL}/admin/network-zone-groups?all=true`,
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      setGroups(res.data.network_zone_groups);
    } catch {
      toast.error("Could not refresh zone groups.");
    }
  };

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDialogOpen(true);
  };

  const openEdit = (group: NetworkZoneGroup) => {
    setEditing(group);
    setForm({ name: group.name, description: group.description || "", is_active: group.is_active });
    setDialogOpen(true);
  };

  const handleSave = async () => {
    if (!authToken) return;
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        is_active: form.is_active,
      };
      if (editing) {
        await axios.patch(`${API_URL}/admin/network-zone-groups/${editing.id}`, payload, {
          headers: { Authorization: `Bearer ${authToken}` },
        });
        toast.success("Zone group updated.");
      } else {
        await axios.post(`${API_URL}/admin/network-zone-groups`, payload, {
          headers: { Authorization: `Bearer ${authToken}` },
        });
        toast.success("Zone group created.");
      }
      setDialogOpen(false);
      await fetchGroups();
    } catch (err) {
      const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
      toast.error(data?.error || "Save failed.");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!authToken || !deleteTarget) return;
    setDeleting(true);
    try {
      await axios.delete(`${API_URL}/admin/network-zone-groups/${deleteTarget.id}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      toast.success("Zone group deleted.");
      setDeleteTarget(null);
      await fetchGroups();
    } catch {
      toast.error("Delete failed.");
    } finally {
      setDeleting(false);
    }
  };

  const addZoneToGroup = async (groupId: number) => {
    const zoneId = addZoneId[groupId];
    if (!zoneId || !authToken) return;
    try {
      await axios.post(
        `${API_URL}/admin/network-zone-groups/${groupId}/zones`,
        { zone_id: Number(zoneId) },
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      setAddZoneId((prev) => ({ ...prev, [groupId]: "" }));
      await fetchGroups();
    } catch (err) {
      const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
      toast.error(data?.error || "Failed to add zone.");
    }
  };

  const removeZoneFromGroup = async (groupId: number, zoneId: number) => {
    if (!authToken) return;
    try {
      await axios.delete(`${API_URL}/admin/network-zone-groups/${groupId}/zones/${zoneId}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      await fetchGroups();
    } catch {
      toast.error("Failed to remove zone.");
    }
  };

  const addAppToGroup = async (groupId: number) => {
    const appId = addAppId[groupId];
    if (!appId || !authToken) return;
    try {
      await axios.post(
        `${API_URL}/admin/network-zone-groups/${groupId}/apps`,
        { app_id: Number(appId) },
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      setAddAppId((prev) => ({ ...prev, [groupId]: "" }));
      await fetchGroups();
    } catch (err) {
      const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
      toast.error(data?.error || "Failed to add app.");
    }
  };

  const removeAppFromGroup = async (groupId: number, appId: number) => {
    if (!authToken) return;
    try {
      await axios.delete(`${API_URL}/admin/network-zone-groups/${groupId}/apps/${appId}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      await fetchGroups();
    } catch {
      toast.error("Failed to remove app.");
    }
  };

  if (!authToken) return null;

  return (
    <div className="p-6 font-montserrat">
      <div className="mb-8 flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-primary/10 text-primary">
            <Layers className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold">Zone Groups</h1>
            <p className="text-sm text-muted-foreground max-w-2xl mt-1">
              Group network zones into logical security boundaries. Add apps to a zone group to
              grant access from all zones in that group. Apps with no zone group mapping are
              inaccessible by default.
            </p>
          </div>
        </div>
        <Button size="sm" onClick={openCreate}>
          <Plus className="h-4 w-4 mr-1" /> New Group
        </Button>
      </div>

      {loading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Loading zone groups…
          </CardContent>
        </Card>
      ) : groups.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No zone groups configured. Create one to start granting app access by network zone.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {groups.map((group) => {
            const memberZoneIds = new Set(group.zones.map((z) => z.id));
            const memberAppIds = new Set(group.apps.map((a) => a.id));
            const availableZones = allZones.filter((z) => !memberZoneIds.has(z.id));
            const availableApps = allApps.filter((a) => !memberAppIds.has(a.id));

            return (
              <Card key={group.id} className={group.is_active ? "" : "opacity-60"}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <CardTitle className="text-base">{group.name}</CardTitle>
                        {!group.is_active && <Badge variant="secondary">Inactive</Badge>}
                      </div>
                      {group.description && (
                        <CardDescription className="mt-1">{group.description}</CardDescription>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Button variant="ghost" size="icon" onClick={() => openEdit(group)}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(group)}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-5">
                  {/* Zones section */}
                  <div>
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2 flex items-center gap-1">
                      <Network className="h-3 w-3" /> Network Zones
                    </p>
                    <div className="flex flex-wrap gap-1 mb-2">
                      {group.zones.length === 0 ? (
                        <span className="text-xs text-muted-foreground italic">No zones added yet</span>
                      ) : (
                        group.zones.map((z) => (
                          <Badge key={z.id} variant="secondary" className="gap-1 text-xs">
                            {z.name}
                            <button
                              onClick={() => removeZoneFromGroup(group.id, z.id)}
                              className="ml-1 hover:text-destructive"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))
                      )}
                    </div>
                    {availableZones.length > 0 && (
                      <div className="flex gap-2">
                        <Select
                          value={addZoneId[group.id] || ""}
                          onValueChange={(v) => setAddZoneId((prev) => ({ ...prev, [group.id]: v }))}
                        >
                          <SelectTrigger className="h-8 text-xs w-48">
                            <SelectValue placeholder="Add a zone…" />
                          </SelectTrigger>
                          <SelectContent>
                            {availableZones.map((z) => (
                              <SelectItem key={z.id} value={String(z.id)} className="text-xs">
                                {z.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-8 text-xs"
                          disabled={!addZoneId[group.id]}
                          onClick={() => addZoneToGroup(group.id)}
                        >
                          Add
                        </Button>
                      </div>
                    )}
                  </div>

                  {/* Apps section */}
                  <div>
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2 flex items-center gap-1">
                      <AppWindow className="h-3 w-3" /> Applications
                    </p>
                    <div className="flex flex-wrap gap-1 mb-2">
                      {group.apps.length === 0 ? (
                        <span className="text-xs text-muted-foreground italic">No apps added yet</span>
                      ) : (
                        group.apps.map((a) => (
                          <Badge key={a.id} variant="secondary" className="gap-1 text-xs">
                            {a.name}
                            <button
                              onClick={() => removeAppFromGroup(group.id, a.id)}
                              className="ml-1 hover:text-destructive"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))
                      )}
                    </div>
                    {availableApps.length > 0 && (
                      <div className="flex gap-2">
                        <Select
                          value={addAppId[group.id] || ""}
                          onValueChange={(v) => setAddAppId((prev) => ({ ...prev, [group.id]: v }))}
                        >
                          <SelectTrigger className="h-8 text-xs w-48">
                            <SelectValue placeholder="Add an app…" />
                          </SelectTrigger>
                          <SelectContent>
                            {availableApps.map((a) => (
                              <SelectItem key={a.id} value={String(a.id)} className="text-xs">
                                {a.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-8 text-xs"
                          disabled={!addAppId[group.id]}
                          onClick={() => addAppToGroup(group.id)}
                        >
                          Add
                        </Button>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create / Edit dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-md font-montserrat">
          <DialogHeader>
            <DialogTitle>{editing ? "Edit Zone Group" : "New Zone Group"}</DialogTitle>
            <DialogDescription>
              {editing
                ? "Update group name and description."
                : "Create a named group to collect zones and grant app access."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1">
              <Label>Name <span className="text-destructive">*</span></Label>
              <Input
                placeholder="e.g. Internal Networks"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="space-y-1">
              <Label>Description <span className="text-muted-foreground text-xs">(optional)</span></Label>
              <Input
                placeholder="Short description"
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Active</p>
                <p className="text-xs text-muted-foreground">Inactive groups are not enforced</p>
              </div>
              <Switch
                checked={form.is_active}
                onCheckedChange={(v) => setForm((f) => ({ ...f, is_active: v }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving || !form.name.trim()}>
              {saving ? "Saving…" : editing ? "Save Changes" : "Create Group"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm dialog */}
      <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
        <DialogContent className="sm:max-w-sm font-montserrat">
          <DialogHeader>
            <DialogTitle>Delete Zone Group</DialogTitle>
            <DialogDescription>
              Delete <strong>{deleteTarget?.name}</strong>? All zone and app memberships in this
              group will be removed. Apps that have no remaining zone group will become inaccessible.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" disabled={deleting} onClick={handleDelete}>
              {deleting ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

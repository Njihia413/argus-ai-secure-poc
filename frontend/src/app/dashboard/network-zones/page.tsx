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
import { Network, Pencil, Plus, Trash2, X } from "lucide-react";
import { API_URL } from "@/app/utils/constants";

interface NetworkZone {
  id: number;
  name: string;
  description: string | null;
  cidrs: string[];
  requires_key: boolean;
  is_active: boolean;
  created_at: string | null;
}

const emptyForm = { name: "", description: "", cidrs: [] as string[], requires_key: false, is_active: true };

export default function NetworkZonesPage() {
  const router = useRouter();
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [zones, setZones] = useState<NetworkZone[]>([]);
  const [loading, setLoading] = useState(true);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<NetworkZone | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [cidrInput, setCidrInput] = useState("");
  const [saving, setSaving] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<NetworkZone | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem("user");
    const user = stored ? JSON.parse(stored) : null;
    if (!user?.authToken) { router.push("/"); return; }
    setAuthToken(user.authToken);
  }, [router]);

  useEffect(() => {
    if (!authToken) return;
    fetchZones();
  }, [authToken]);

  const fetchZones = async () => {
    setLoading(true);
    try {
      const res = await axios.get<{ zones: NetworkZone[] }>(
        `${API_URL}/admin/network-zones`,
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      setZones(res.data.zones);
    } catch (err) {
      const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
      toast.error(data?.error || "Could not load network zones.");
    } finally {
      setLoading(false);
    }
  };

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setCidrInput("");
    setDialogOpen(true);
  };

  const openEdit = (zone: NetworkZone) => {
    setEditing(zone);
    setForm({ name: zone.name, description: zone.description || "", cidrs: [...zone.cidrs], requires_key: zone.requires_key, is_active: zone.is_active });
    setCidrInput("");
    setDialogOpen(true);
  };

  const normalizeCidr = (input: string): string => {
    if (input.includes("/")) return input;
    // Plain IP — convert to host CIDR (/32 for IPv4, /128 for IPv6)
    return input.includes(":") ? `${input}/128` : `${input}/32`;
  };

  const addCidr = () => {
    const val = cidrInput.trim();
    if (!val) return;
    const normalized = normalizeCidr(val);
    if (form.cidrs.includes(normalized)) { setCidrInput(""); return; }
    setForm((f) => ({ ...f, cidrs: [...f.cidrs, normalized] }));
    setCidrInput("");
  };

  const removeCidr = (cidr: string) => {
    setForm((f) => ({ ...f, cidrs: f.cidrs.filter((c) => c !== cidr) }));
  };

  const handleSave = async () => {
    if (!authToken) return;
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        cidrs: form.cidrs,
        requires_key: form.requires_key,
        is_active: form.is_active,
      };
      if (editing) {
        await axios.patch(`${API_URL}/admin/network-zones/${editing.id}`, payload, {
          headers: { Authorization: `Bearer ${authToken}` },
        });
        toast.success("Zone updated.");
      } else {
        await axios.post(`${API_URL}/admin/network-zones`, payload, {
          headers: { Authorization: `Bearer ${authToken}` },
        });
        toast.success("Zone created.");
      }
      setDialogOpen(false);
      fetchZones();
    } catch (err) {
      const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
      toast.error(data?.error || "Save failed.");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!authToken || !deleteTarget) return;
    try {
      await axios.delete(`${API_URL}/admin/network-zones/${deleteTarget.id}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      toast.success("Zone deleted.");
      setDeleteTarget(null);
      fetchZones();
    } catch {
      toast.error("Delete failed.");
    }
  };

  if (!authToken) return null;

  return (
    <div className="p-6 font-montserrat">
      <div className="mb-8 flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-primary/10 text-primary">
            <Network className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold">Network Zones</h1>
            <p className="text-sm text-muted-foreground max-w-2xl mt-1">
              Define network zones by individual IP addresses or CIDR ranges. Assign zones to
              registered apps to restrict access based on where requests originate. Zones can
              optionally require a security key.
            </p>
          </div>
        </div>
        <Button size="sm" onClick={openCreate}>
          <Plus className="h-4 w-4 mr-1" /> New Zone
        </Button>
      </div>

      {loading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Loading zones…
          </CardContent>
        </Card>
      ) : zones.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No network zones configured. Create one to start restricting resource access by network.
          </CardContent>
        </Card>
      ) : (
        <>
        <div className="space-y-4">
          {zones.map((zone) => (
            <Card key={zone.id} className={zone.is_active ? "" : "opacity-60"}>
              <CardHeader>
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <CardTitle className="text-base">{zone.name}</CardTitle>
                      {!zone.is_active && <Badge variant="secondary">Inactive</Badge>}
                      {zone.requires_key && (
                        <Badge variant="outline" className="text-xs">Requires Key</Badge>
                      )}
                    </div>
                    {zone.description && (
                      <CardDescription className="mt-1">{zone.description}</CardDescription>
                    )}
                    <div className="mt-2 flex flex-wrap gap-1">
                      {zone.cidrs.length === 0 ? (
                        <span className="text-xs text-muted-foreground italic">No CIDRs defined</span>
                      ) : (
                        zone.cidrs.map((cidr) => (
                          <Badge key={cidr} variant="secondary" className="font-mono text-xs">
                            {cidr}
                          </Badge>
                        ))
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Button variant="ghost" size="icon" onClick={() => openEdit(zone)}>
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(zone)}>
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
            </Card>
          ))}
        </div>
        </>
      )}

      {/* Create / Edit dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-md font-montserrat">
          <DialogHeader>
            <DialogTitle>{editing ? "Edit Zone" : "New Network Zone"}</DialogTitle>
            <DialogDescription>
              {editing ? "Update zone configuration." : "Define a zone by name and CIDR ranges."}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input
                placeholder="e.g. Corporate LAN"
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

            <div className="space-y-2">
              <Label>IP Addresses / CIDR Ranges</Label>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g. 192.168.1.100 or 192.168.1.0/24"
                  value={cidrInput}
                  onChange={(e) => setCidrInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addCidr(); } }}
                  className="font-mono text-sm"
                />
                <Button type="button" variant="outline" size="sm" onClick={addCidr}>Add</Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Enter a single IP (e.g. 10.0.0.5) or a CIDR range (e.g. 10.0.0.0/8). Single IPs are stored as /32.
              </p>
              {form.cidrs.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {form.cidrs.map((cidr) => (
                    <Badge key={cidr} variant="secondary" className="font-mono text-xs gap-1">
                      {cidr}
                      <button onClick={() => removeCidr(cidr)} className="ml-1 hover:text-destructive">
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Requires Security Key</p>
                <p className="text-xs text-muted-foreground">Block access from this zone if no key is present</p>
              </div>
              <Switch
                checked={form.requires_key}
                onCheckedChange={(v) => setForm((f) => ({ ...f, requires_key: v }))}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Active</p>
                <p className="text-xs text-muted-foreground">Inactive zones are not enforced</p>
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
              {saving ? "Saving…" : editing ? "Save Changes" : "Create Zone"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm dialog */}
      <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
        <DialogContent className="sm:max-w-sm font-montserrat">
          <DialogHeader>
            <DialogTitle>Delete Zone</DialogTitle>
            <DialogDescription>
              Delete <strong>{deleteTarget?.name}</strong>? Any models or apps assigned to this zone
              will have their zone requirement cleared.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete}>Delete</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

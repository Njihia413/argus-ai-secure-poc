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
import { Separator } from "@/components/ui/separator";
import { ChevronDown, ChevronRight, Shield } from "lucide-react";
import { API_URL } from "@/app/utils/constants";
import { Tier, TierPill } from "@/app/utils/tiers";

interface AIModel {
  id: number;
  slug: string;
  display_name: string;
  min_tier: Tier;
  is_active: boolean;
}

interface AppFeature {
  id: number;
  slug: string;
  display_name: string;
  min_tier: Tier;
  is_active: boolean;
}

interface AppItem {
  id: number;
  slug: string;
  display_name: string;
  min_tier: Tier;
  is_active: boolean;
  features: AppFeature[];
}

interface RolePermissions {
  role: string;
  models: string[];
  apps: string[];
  app_features: string[];
  admin_sections: string[];
}

const ROLES: { slug: string; label: string; blurb: string }[] = [
  { slug: "admin", label: "Admin", blurb: "Full system control." },
  { slug: "it_department", label: "IT Department", blurb: "Technical tooling and admin helpers." },
  { slug: "manager", label: "Manager", blurb: "Team leads - productivity apps + larger models." },
  { slug: "hr", label: "HR", blurb: "People ops - mail merge, Outlook, no macros." },
  { slug: "customer_service", label: "Customer Service", blurb: "Light tooling, small models only." },
];

const ADMIN_SECTIONS: { slug: string; label: string }[] = [
  { slug: "user_mgmt", label: "User management" },
  { slug: "audit_logs", label: "Audit logs" },
  { slug: "key_mgmt", label: "Security keys" },
  { slug: "lockdown", label: "Emergency lockdown" },
];

export default function RolesPage() {
  const router = useRouter();
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [selectedRole, setSelectedRole] = useState<string>("admin");
  const [models, setModels] = useState<AIModel[]>([]);
  const [apps, setApps] = useState<AppItem[]>([]);
  const [perms, setPerms] = useState<RolePermissions | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [notAdmin, setNotAdmin] = useState(false);

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

  useEffect(() => {
    if (!authToken) return;
    const headers = { Authorization: `Bearer ${authToken}` };
    (async () => {
      try {
        const [m, a] = await Promise.all([
          axios.get<{ models: AIModel[] }>(`${API_URL}/admin/ai-models`, { headers }),
          axios.get<{ applications: AppItem[] }>(`${API_URL}/admin/applications`, { headers }),
        ]);
        setModels(m.data.models);
        setApps(a.data.applications);
      } catch (err) {
        const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
        toast.error(data?.error || "Could not load catalog.");
      }
    })();
  }, [authToken]);

  useEffect(() => {
    if (!authToken) return;
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
  const activeApps = useMemo(
    () =>
      apps
        .filter((a) => a.is_active)
        .map((a) => ({ ...a, features: a.features.filter((f) => f.is_active) })),
    [apps],
  );

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
          app_features: perms.app_features,
          admin_sections: perms.admin_sections,
        },
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      toast.success(`Permissions saved for ${selectedRole}.`);
    } catch {
      toast.error("Failed to save permissions.");
    } finally {
      setSaving(false);
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
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground px-1">
            Roles
          </p>
          {ROLES.map((r) => {
            const active = selectedRole === r.slug;
            return (
              <button
                key={r.slug}
                onClick={() => setSelectedRole(r.slug)}
                className={`w-full text-left p-3 rounded-xl border transition-colors ${
                  active
                    ? "border-primary bg-primary/5"
                    : "border-zinc-200 dark:border-zinc-800 hover:bg-muted/50"
                }`}
              >
                <div className="text-sm font-medium">{r.label}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{r.blurb}</div>
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
                    {ROLES.find((r) => r.slug === selectedRole)?.label}
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

              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base">Desktop applications</CardTitle>
                      <CardDescription className="mt-1">
                        Apps only appear on a user&apos;s dashboard when the admin has bound their
                        workstation and the app is actually detected there.
                      </CardDescription>
                    </div>
                    <Badge variant="outline" className="ml-4">
                      {perms.apps.filter((slug) => activeApps.some((a) => a.slug === slug)).length} / {activeApps.length} allowed
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {activeApps.map((a) => {
                      const isOpen = expanded[a.slug] ?? false;
                      return (
                        <div
                          key={a.slug}
                          className="rounded-xl border border-zinc-200 dark:border-zinc-800"
                        >
                          <div className="flex items-center gap-3 p-3">
                            <Checkbox
                              checked={perms.apps.includes(a.slug)}
                              onCheckedChange={() => toggle("apps", a.slug)}
                            />
                            <button
                              type="button"
                              onClick={() =>
                                setExpanded((prev) => ({ ...prev, [a.slug]: !isOpen }))
                              }
                              className="flex-1 flex items-center gap-2 text-left min-w-0"
                            >
                              {isOpen ? (
                                <ChevronDown className="h-4 w-4 shrink-0" />
                              ) : (
                                <ChevronRight className="h-4 w-4 shrink-0" />
                              )}
                              <div className="min-w-0">
                                <div className="text-sm font-medium truncate">
                                  {a.display_name}
                                </div>
                                <div className="text-xs text-muted-foreground font-mono truncate">
                                  {a.slug}
                                </div>
                              </div>
                            </button>
                            <TierPill tier={a.min_tier} />
                          </div>
                          {isOpen && (
                            <>
                              <Separator />
                              <div className="p-3 pl-11 bg-muted/30 rounded-b-xl">
                                {a.features.length === 0 ? (
                                  <div className="text-xs text-muted-foreground">
                                    No features defined for this application.
                                  </div>
                                ) : (
                                  <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                                    {a.features.map((f) => (
                                      <label
                                        key={f.slug}
                                        className="flex items-center gap-3 py-2 cursor-pointer"
                                      >
                                        <Checkbox
                                          checked={perms.app_features.includes(f.slug)}
                                          onCheckedChange={() => toggle("app_features", f.slug)}
                                        />
                                        <div className="flex-1 min-w-0">
                                          <div className="text-sm">{f.display_name}</div>
                                          <div className="text-xs text-muted-foreground font-mono truncate">
                                            {f.slug}
                                          </div>
                                        </div>
                                        <TierPill tier={f.min_tier} />
                                      </label>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>

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
                        {perms.admin_sections.length} / {ADMIN_SECTIONS.length} allowed
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                      {ADMIN_SECTIONS.map((s) => (
                        <label
                          key={s.slug}
                          className="flex items-center gap-3 py-3 cursor-pointer"
                        >
                          <Checkbox
                            checked={perms.admin_sections.includes(s.slug)}
                            onCheckedChange={() => toggle("admin_sections", s.slug)}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium">{s.label}</div>
                            <div className="text-xs text-muted-foreground font-mono">{s.slug}</div>
                          </div>
                        </label>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

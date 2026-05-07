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
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AppWindow, KeyRound, Rocket } from "lucide-react";
import { API_URL } from "@/app/utils/constants";
import { Tier, tierLabel, TierPill } from "@/app/utils/tiers";

interface AccessApplication {
  slug: string;
  display_name: string;
  min_tier: Tier;
  launch_uri: string | null;
}

interface AccessApplicationsResponse {
  tier: Tier;
  applications: AccessApplication[];
}

interface CatalogFeature {
  id: number;
  slug: string;
  display_name: string;
  min_tier: Tier;
  is_active: boolean;
}

interface CatalogApp {
  id: number;
  slug: string;
  display_name: string;
  min_tier: Tier;
  is_active: boolean;
  detect_hints: Record<string, string> | null;
  features: CatalogFeature[];
}

export default function ApplicationsPage() {
  const router = useRouter();
  const [role, setRole] = useState<string | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem("user");
    const user = stored ? JSON.parse(stored) : null;
    if (!user?.authToken) {
      router.push("/");
      return;
    }
    setRole(user.role);
    setAuthToken(user.authToken);
  }, [router]);

  if (!authToken || !role) {
    return (
      <div className="p-6 font-montserrat">
        <p className="text-sm text-muted-foreground">Loading…</p>
      </div>
    );
  }

  return role === "admin" ? (
    <AdminCatalog authToken={authToken} />
  ) : (
    <UserLauncher authToken={authToken} />
  );
}

/* ---------- Admin catalog editor ---------- */

function AdminCatalog({ authToken }: { authToken: string }) {
  const [apps, setApps] = useState<CatalogApp[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const res = await axios.get<{ applications: CatalogApp[] }>(
          `${API_URL}/admin/applications`,
          { headers: { Authorization: `Bearer ${authToken}` } },
        );
        setApps(res.data.applications);
      } catch (err) {
        const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
        toast.error(data?.error || "Could not load application catalog.");
      } finally {
        setLoading(false);
      }
    })();
  }, [authToken]);

  const patchApp = async (app: CatalogApp, patch: Partial<CatalogApp>) => {
    try {
      const res = await axios.patch<CatalogApp>(
        `${API_URL}/admin/applications/${app.id}`,
        patch,
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      setApps((prev) =>
        prev.map((a) => (a.id === app.id ? { ...a, ...res.data, features: a.features } : a)),
      );
      toast.success(`${app.display_name} updated.`);
    } catch {
      toast.error("Update failed.");
    }
  };

  const patchFeature = async (
    appId: number,
    feature: CatalogFeature,
    patch: Partial<CatalogFeature>,
  ) => {
    try {
      const res = await axios.patch<CatalogFeature>(
        `${API_URL}/admin/application-features/${feature.id}`,
        patch,
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      setApps((prev) =>
        prev.map((a) =>
          a.id !== appId
            ? a
            : {
                ...a,
                features: a.features.map((f) =>
                  f.id === feature.id ? { ...f, ...res.data } : f,
                ),
              },
        ),
      );
    } catch {
      toast.error("Feature update failed.");
    }
  };

  return (
    <div className="p-6 font-montserrat">
      <div className="mb-8 flex items-start gap-3">
        <div className="p-2 rounded-lg bg-primary/10 text-primary">
          <AppWindow className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">Application catalog</h1>
          <p className="text-sm text-muted-foreground max-w-3xl mt-1">
            The master list of desktop applications Argus recognises. An app appears on a
            user&apos;s dashboard only when (1) it is active here, (2) their role is allowed in{" "}
            <strong>Roles</strong>, and (3) it is actually installed on their bound workstation.
          </p>
        </div>
      </div>

      {loading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Loading catalog…
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {apps.map((app) => (
            <Card key={app.id} className={!app.is_active ? "opacity-60" : ""}>
              <CardHeader>
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <CardTitle className="text-base">{app.display_name}</CardTitle>
                      <TierPill tier={app.min_tier} />
                      {!app.is_active && (
                        <Badge variant="outline" className="text-xs">
                          inactive
                        </Badge>
                      )}
                    </div>
                    <CardDescription className="mt-1 font-mono text-xs truncate">
                      {app.slug}
                      {app.detect_hints?.launch_uri ? (
                        <>
                          {" · "}launch: <code>{app.detect_hints.launch_uri}</code>
                        </>
                      ) : null}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <label className="flex items-center gap-2 text-xs text-muted-foreground">
                      Active
                      <Switch
                        checked={app.is_active}
                        onCheckedChange={(v) => patchApp(app, { is_active: v })}
                      />
                    </label>
                    <Select
                      value={app.min_tier}
                      onValueChange={(v) => patchApp(app, { min_tier: v as Tier })}
                    >
                      <SelectTrigger className="h-8 w-[170px] text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">{tierLabel.none}</SelectItem>
                        <SelectItem value="key_unbound">{tierLabel.key_unbound}</SelectItem>
                        <SelectItem value="key_bound">{tierLabel.key_bound}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
              {app.features.length > 0 && (
                <CardContent>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                    Features
                  </p>
                  <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                    {app.features.map((f) => (
                      <div key={f.id} className="flex items-center gap-3 py-2">
                        <div className="flex-1 min-w-0">
                          <div className="text-sm">{f.display_name}</div>
                          <div className="text-xs text-muted-foreground font-mono truncate">
                            {f.slug}
                          </div>
                        </div>
                        <Select
                          value={f.min_tier}
                          onValueChange={(v) =>
                            patchFeature(app.id, f, { min_tier: v as Tier })
                          }
                        >
                          <SelectTrigger className="h-8 w-[170px] text-xs">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="none">{tierLabel.none}</SelectItem>
                            <SelectItem value="key_unbound">{tierLabel.key_unbound}</SelectItem>
                            <SelectItem value="key_bound">{tierLabel.key_bound}</SelectItem>
                          </SelectContent>
                        </Select>
                        <label className="flex items-center gap-2 text-xs text-muted-foreground">
                          Active
                          <Switch
                            checked={f.is_active}
                            onCheckedChange={(v) =>
                              patchFeature(app.id, f, { is_active: v })
                            }
                          />
                        </label>
                      </div>
                    ))}
                  </div>
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------- End-user launcher ---------- */

function UserLauncher({ authToken }: { authToken: string }) {
  const [tier, setTier] = useState<Tier>("none");
  const [apps, setApps] = useState<AccessApplication[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fp = sessionStorage.getItem("workstation_fingerprint");
    const machineId = fp ? (JSON.parse(fp)?.machine_id ?? "") : "";

    axios
      .get<AccessApplicationsResponse>(`${API_URL}/access/applications`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
          ...(machineId ? { "X-Machine-Id": machineId } : {}),
        },
      })
      .then((res) => {
        setTier(res.data.tier);
        setApps(res.data.applications);
        setLoading(false);
      })
      .catch(() => {
        toast.error("Could not load applications.");
        setLoading(false);
      });
  }, [authToken]);

  const launch = (app: AccessApplication) => {
    if (!app.launch_uri) {
      toast.error(`${app.display_name} has no configured launch URI.`);
      return;
    }
    const a = document.createElement("a");
    a.href = app.launch_uri;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div className="p-6 font-montserrat">
      <div className="mb-8 flex items-start gap-3">
        <div className="p-2 rounded-lg bg-primary/10 text-primary">
          <Rocket className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">Applications</h1>
          <p className="text-sm text-muted-foreground">
            Desktop applications you are authorised to launch from this workstation.
          </p>
        </div>
      </div>

      {loading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Loading…
          </CardContent>
        </Card>
      ) : tier !== "key_bound" ? (
        <Card className="border-amber-500/30 bg-amber-500/5 max-w-2xl">
          <CardHeader>
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-400">
                <KeyRound className="h-5 w-5" />
              </div>
              <div>
                <CardTitle>Sign in with your security key on a registered machine</CardTitle>
                <CardDescription className="mt-1">
                  Enterprise applications only appear once you&apos;ve verified your security key
                  and you&apos;re on a workstation that has been bound to it. Your current session
                  is at tier <code>{tier}</code>.
                </CardDescription>
              </div>
            </div>
          </CardHeader>
        </Card>
      ) : apps.length === 0 ? (
        <Card className="max-w-2xl">
          <CardHeader>
            <CardTitle>No installed applications detected</CardTitle>
            <CardDescription className="mt-1">
              This workstation hasn&apos;t reported any of the applications your role is allowed
              to launch. Ask your administrator to verify the application inventory for this
              machine.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {apps.map((app) => (
            <Card key={app.slug}>
              <CardHeader>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <CardTitle className="text-base truncate">{app.display_name}</CardTitle>
                    <CardDescription className="font-mono text-xs truncate">
                      {app.slug}
                    </CardDescription>
                  </div>
                  <TierPill tier={app.min_tier} />
                </div>
              </CardHeader>
              <CardContent>
                <Button
                  onClick={() => launch(app)}
                  disabled={!app.launch_uri}
                  className="w-full"
                >
                  Launch
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

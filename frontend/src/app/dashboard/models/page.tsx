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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Cpu } from "lucide-react";
import { API_URL } from "@/app/utils/constants";
import { Tier, TIER_VALUES, tierLabel, TierPill } from "@/app/utils/tiers";

interface AIModel {
  id: number;
  slug: string;
  display_name: string;
  min_tier: Tier;
  is_active: boolean;
}

export default function ModelsPage() {
  const router = useRouter();
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [models, setModels] = useState<AIModel[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const stored = sessionStorage.getItem("user");
    const user = stored ? JSON.parse(stored) : null;
    if (!user?.authToken) {
      router.push("/");
      return;
    }
    setAuthToken(user.authToken);
  }, [router]);

  useEffect(() => {
    if (!authToken) return;
    (async () => {
      setLoading(true);
      try {
        const res = await axios.get<{ models: AIModel[] }>(
          `${API_URL}/admin/ai-models`,
          { headers: { Authorization: `Bearer ${authToken}` } },
        );
        setModels(res.data.models.filter((m) => m.is_active));
      } catch (err) {
        const data = (err as { response?: { data?: { error?: string } } })?.response?.data;
        toast.error(data?.error || "Could not load models.");
      } finally {
        setLoading(false);
      }
    })();
  }, [authToken]);

  const patchModel = async (model: AIModel, patch: Partial<AIModel>) => {
    if (!authToken) return;
    try {
      const res = await axios.patch<AIModel>(
        `${API_URL}/admin/ai-models/${model.id}`,
        patch,
        { headers: { Authorization: `Bearer ${authToken}` } },
      );
      setModels((prev) => prev.map((m) => (m.id === model.id ? { ...m, ...res.data } : m)));
      toast.success(`${model.display_name} updated.`);
    } catch {
      toast.error("Update failed.");
    }
  };

  if (!authToken) {
    return (
      <div className="p-6 font-montserrat">
        <p className="text-sm text-muted-foreground">Loading…</p>
      </div>
    );
  }

  return (
    <div className="p-6 font-montserrat">
      <div className="mb-8 flex items-start gap-3">
        <div className="p-2 rounded-lg bg-primary/10 text-primary">
          <Cpu className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">AI Models</h1>
          <p className="text-sm text-muted-foreground max-w-3xl mt-1">
            Configure the security tier required for each Groq model. A user can only chat with
            a model if (1) their role allows it in <strong>Roles</strong>, and (2) their current
            login tier meets the minimum tier set here.
          </p>
        </div>
      </div>

      {loading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Loading models…
          </CardContent>
        </Card>
      ) : models.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No models registered.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {models.map((model) => (
            <Card key={model.id}>
              <CardHeader>
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <CardTitle className="text-base">{model.display_name}</CardTitle>
                      <TierPill tier={model.min_tier} />
                    </div>
                    <CardDescription className="mt-1 font-mono text-xs truncate">
                      {model.slug}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <Select
                      value={model.min_tier}
                      onValueChange={(v) => patchModel(model, { min_tier: v as Tier })}
                    >
                      <SelectTrigger className="h-8 w-[170px] text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {TIER_VALUES.map((t) => (
                          <SelectItem key={t} value={t}>
                            {tierLabel[t]}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

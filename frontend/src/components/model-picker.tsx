"use client";
import { modelID } from "@/ai/providers";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";

// Type for model dictionaries - make it a partial record to allow subsets of models
type ModelDict = Partial<Record<modelID, string>>;

interface ModelPickerProps {
  selectedModel: modelID;
  setSelectedModel: (model: modelID) => void;
  models: ModelDict;
  tier?: "none" | "key_unbound" | "key_bound";
}

const TIER_DOT: Record<string, { color: string; label: string }> = {
  none: { color: "bg-zinc-400", label: "Password only" },
  key_unbound: { color: "bg-amber-500", label: "Key verified" },
  key_bound: { color: "bg-emerald-500", label: "Key + bound machine" },
};

export const ModelPicker = ({
                              selectedModel,
                              setSelectedModel,
                              models,
                              tier,
                            }: ModelPickerProps) => {
  const getModelDisplay = (modelId: string) => {
    return models[modelId as modelID] || modelId;
  };

  const dot = tier ? TIER_DOT[tier] : null;

  return (
      <div className="absolute bottom-2 left-2 flex items-center gap-2">
        {dot && (
          <span
            className={`h-2 w-2 rounded-full ${dot.color}`}
            title={dot.label}
            aria-label={`Access tier: ${dot.label}`}
          />
        )}
        <Select value={selectedModel} onValueChange={setSelectedModel}>
          <SelectTrigger className="">
            <SelectValue placeholder="Select a model">
              {getModelDisplay(selectedModel)}
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {/* Use the models prop here */}
              {Object.entries(models).map(([modelId, modelName]) => (
                  <SelectItem key={modelId} value={modelId}>
                    {modelName || modelId}
                  </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      </div>
  );
};

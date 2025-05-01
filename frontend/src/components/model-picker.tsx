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
}

export const ModelPicker = ({
                              selectedModel,
                              setSelectedModel,
                              models, // Destructure models prop
                            }: ModelPickerProps) => {
  // Display model name if available in models dictionary, otherwise show model ID
  const getModelDisplay = (modelId: string) => {
    return models[modelId as modelID] || modelId;
  };

  return (
      <div className="absolute bottom-2 left-2 flex flex-col gap-2">
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

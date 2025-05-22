import { modelID } from "@/ai/providers";
import { Textarea as ShadcnTextarea } from "@/components/ui/textarea";
import { ArrowUp } from "lucide-react";
import { ModelPicker } from "./model-picker";

// Type for model dictionaries
type ModelDict = Partial<Record<modelID, string>>;

interface InputProps {
  input: string;
  handleInputChange: (event: React.ChangeEvent<HTMLInputElement>) => void;
  isLoading: boolean;
  status: string;
  stop: () => void;
  selectedModel: modelID;
  setSelectedModel: (model: modelID) => void;
  models: ModelDict;
}

export const Textarea = ({
  input,
  handleInputChange,
  isLoading,
  status,
  stop,
  selectedModel,
  setSelectedModel,
  models, // Destructure models
}: InputProps) => {
  return (
    <div className="relative w-full pt-4">
      <ShadcnTextarea
        className="resize-none bg-secondary w-full rounded-xl pr-12 pt-4 pb-16"
        value={input}
        autoFocus
        placeholder={"Say something..."}
        // @ts-expect-error err
        onChange={handleInputChange}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            if (input.trim() && !isLoading) {
              // @ts-expect-error err
              const form = e.target.closest("form");
              if (form) form.requestSubmit();
            }
          }
        }}
      />
      <ModelPicker
        setSelectedModel={setSelectedModel}
        selectedModel={selectedModel}
        models={models} // Pass models down
      />

      {status === "streaming" || status === "submitted" ? (
        <button
          type="button"
          onClick={stop}
          className="cursor-pointer absolute right-2 bottom-2 rounded-full p-2 bg-primary hover:bg-primary/90 disabled:bg-primary/50 disabled:cursor-not-allowed transition-colors"
        >
          <div className="animate-spin h-4 w-4">
            <svg className="h-4 w-4 text-white" viewBox="0 0 24 24">
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
                fill="none"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
          </div>
        </button>
      ) : (
        <button
          type="submit"
          disabled={isLoading || !input.trim()}
          className="absolute right-2 bottom-2 rounded-full p-2 bg-primary hover:bg-primary/90 disabled:bg-primary/50 disabled:cursor-not-allowed transition-colors"
        >
          <ArrowUp className="h-4 w-4 text-primary-foreground" />
        </button>
      )}
    </div>
  );
};

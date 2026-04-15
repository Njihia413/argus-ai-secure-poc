import type { Message as TMessage } from "ai";
import { Message } from "./message";
import { useScrollToBottom } from "@/lib/hooks/use-scroll-to-bottom";
import { ThreeDots } from "react-loader-spinner";

export const Messages = ({
  messages,
  isLoading,
  status,
}: {
  messages: TMessage[];
  isLoading: boolean;
  status: "error" | "submitted" | "streaming" | "ready";
}) => {
  const [containerRef, endRef] = useScrollToBottom();
  return (
    <div
      className="flex-1 h-full space-y-4 overflow-y-auto pt-20 pb-8"
      ref={containerRef}
    >
      <div className="max-w-xl mx-auto">
        {messages.map((m, i) => (
          <Message
            key={i}
            isLatestMessage={i === messages.length - 1}
            isLoading={isLoading}
            message={m}
            status={status}
          />
        ))}

        {/* Typing indicator — shown while waiting for or streaming a response */}
        {(status === "submitted" || (status === "streaming" && messages.length > 0 && messages[messages.length - 1].role === "user")) && (
          <div className="flex gap-4 w-full px-4 py-2">
            <div className="size-8 flex items-center rounded-xl justify-center ring-1 shrink-0 ring-border bg-background">
              <img src="/assets/images/Logo-No-Bg.png" alt="Logo" className="h-6"/>
            </div>
            <div className="flex items-center bg-zinc-100 dark:bg-zinc-800 px-3 py-2 rounded-tl-xl rounded-tr-xl rounded-br-xl">
              <ThreeDots height="24" width="36" color="currentColor" ariaLabel="typing" />
            </div>
          </div>
        )}
        <div className="h-1" ref={endRef} />
      </div>
    </div>
  );
};

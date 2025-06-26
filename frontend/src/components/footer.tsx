export function Footer() {
  return (
    <footer className="relative z-20 w-full py-4 text-center text-sm text-zinc-600 dark:text-zinc-400">
      By using Argus AI, you agree to our{" "}
      <a
        href="/terms"
        className="underline hover:text-zinc-900 dark:hover:text-zinc-200"
      >
        Terms
      </a>{" "}
      and have read our{" "}
      <a
        href="/privacy"
        className="underline hover:text-zinc-900 dark:hover:text-zinc-200"
      >
        Privacy Policy
      </a>
    </footer>
  );
}
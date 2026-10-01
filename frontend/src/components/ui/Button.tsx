import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  isLoading?: boolean;
  icon?: ReactNode;
}

const base =
  "inline-flex items-center justify-center gap-2 rounded-lg font-medium " +
  "transition-[transform,opacity,box-shadow,background-color] duration-150 " +
  "ease-[cubic-bezier(0.34,1.56,0.64,1)] active:scale-[0.97] " +
  "disabled:cursor-not-allowed disabled:opacity-50 disabled:active:scale-100 " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-400 focus-visible:ring-offset-2 focus-visible:ring-offset-ink-950";

const variants: Record<Variant, string> = {
  primary:
    "bg-signal-500 text-ink-950 shadow-[0_1px_0_rgba(255,255,255,0.15)_inset,0_4px_14px_rgba(31,174,132,0.35)] hover:bg-signal-400 hover:shadow-[0_1px_0_rgba(255,255,255,0.2)_inset,0_6px_20px_rgba(31,174,132,0.45)] active:bg-signal-600",
  secondary:
    "bg-ink-750 text-ink-100 shadow-elevated border border-ink-600 hover:bg-ink-700 hover:border-ink-500 active:bg-ink-800",
  ghost:
    "bg-transparent text-ink-300 hover:bg-ink-800 hover:text-ink-100 active:bg-ink-750",
  danger:
    "bg-severity-critical/90 text-ink-50 shadow-[0_4px_14px_rgba(228,54,75,0.35)] hover:bg-severity-critical active:bg-severity-critical/80",
};

const sizes: Record<Size, string> = {
  sm: "h-8 px-3 text-sm",
  md: "h-10 px-4 text-sm",
  lg: "h-12 px-6 text-base",
};

export function Button({
  variant = "primary",
  size = "md",
  isLoading = false,
  icon,
  disabled,
  children,
  className = "",
  ...rest
}: ButtonProps) {
  return (
    <button
      className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
      disabled={disabled || isLoading}
      aria-busy={isLoading}
      {...rest}
    >
      {isLoading ? (
        <span
          className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
          aria-hidden="true"
        />
      ) : (
        icon
      )}
      {children}
    </button>
  );
}

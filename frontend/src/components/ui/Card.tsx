import type { HTMLAttributes, ReactNode } from "react";

type Elevation = "base" | "elevated" | "floating";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  elevation?: Elevation;
  children: ReactNode;
}

const elevations: Record<Elevation, string> = {
  base: "bg-ink-850 border border-ink-650",
  elevated: "bg-ink-800 border border-ink-650 shadow-elevated",
  floating: "bg-ink-750 border border-ink-600 shadow-floating",
};

export function Card({ elevation = "elevated", className = "", children, ...rest }: CardProps) {
  return (
    <div className={`rounded-xl ${elevations[elevation]} ${className}`} {...rest}>
      {children}
    </div>
  );
}

export function CardHeader({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`flex items-center justify-between gap-3 border-b border-ink-650 px-5 py-4 ${className}`}>
      {children}
    </div>
  );
}

export function CardBody({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`px-5 py-4 ${className}`}>{children}</div>;
}

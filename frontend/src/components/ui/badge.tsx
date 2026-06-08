import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "@/lib/cn";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium",
  {
    variants: {
      tone: {
        neutral: "border-border bg-[#172033] text-fg-subtle",
        critical: "border-critical/30 bg-critical/15 text-critical",
        high: "border-high/30 bg-high/15 text-high",
        medium: "border-medium/30 bg-medium/15 text-medium",
        low: "border-low/30 bg-low/15 text-low",
        info: "border-info/30 bg-info/15 text-info",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}

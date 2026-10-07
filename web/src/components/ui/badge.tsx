import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[10px] font-mono font-medium transition-colors focus:outline-none focus:ring-1 focus:ring-zinc-400",
  {
    variants: {
      variant: {
        default:
          "border-zinc-700 bg-zinc-800 text-zinc-200",
        secondary:
          "border-zinc-800 bg-zinc-900 text-zinc-400",
        destructive:
          "border-red-900/50 bg-red-950/60 text-red-400",
        emerald:
          "border-emerald-900/50 bg-emerald-950/60 text-emerald-400",
        amber:
          "border-amber-900/50 bg-amber-950/60 text-amber-400",
        pro:
          "border-blue-900/50 bg-blue-950/60 text-blue-400",
        outline: "border-zinc-800 text-zinc-400",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };

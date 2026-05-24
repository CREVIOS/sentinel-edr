"use client";

import { Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * The "watch / inspect" affordance — an eye, fitting for a surveillance console. Used as the
 * row-level detail trigger across tables; on hover it lights up in the primary signal color.
 */
export function Inspect({
  onClick,
  label = "Inspect",
  className,
}: {
  onClick?: () => void;
  label?: string;
  className?: string;
}) {
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      onClick={onClick}
      title={label}
      aria-label={label}
      className={cn(
        "group/eye text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary",
        className,
      )}
    >
      <Eye className="size-4 transition-transform group-hover/eye:scale-110" />
    </Button>
  );
}

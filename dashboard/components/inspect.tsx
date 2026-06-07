"use client";

import { Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Row-level detail trigger used across the data tables. Renders a ghost icon button;
 * hover applies the primary accent.
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
        "text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary",
        className,
      )}
    >
      <Eye className="size-4" strokeWidth={1.75} />
    </Button>
  );
}

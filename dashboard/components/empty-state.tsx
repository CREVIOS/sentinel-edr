"use client";

import * as React from "react";
import { Inbox } from "lucide-react";
import { Button } from "@/components/ui/button";

/**
 * Shared empty / zero-data state. Distinguishes "nothing here yet" (onboarding) from
 * "nothing matches your filters" (offer a reset) and always offers a next step, so empty
 * screens read as guidance rather than dead ends.
 */
export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className,
}: {
  icon?: React.ComponentType<{ className?: string; strokeWidth?: number }>;
  title: string;
  description?: React.ReactNode;
  action?: { label: string; onClick: () => void } | React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`flex flex-col items-center justify-center gap-2 px-6 py-14 text-center ${className ?? ""}`}>
      <span className="mb-1 flex size-11 items-center justify-center rounded-full bg-muted/60">
        <Icon className="size-5 text-muted-foreground" strokeWidth={1.75} />
      </span>
      <p className="text-sm font-medium">{title}</p>
      {description && <p className="max-w-sm text-sm text-muted-foreground">{description}</p>}
      {action &&
        (React.isValidElement(action) ? (
          <div className="mt-2">{action}</div>
        ) : (
          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            onClick={(action as { onClick: () => void }).onClick}
          >
            {(action as { label: string }).label}
          </Button>
        ))}
    </div>
  );
}

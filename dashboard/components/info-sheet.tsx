"use client";

import * as React from "react";
import {
  Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import { Separator } from "@/components/ui/separator";

export type Field = { label: string; value: React.ReactNode; mono?: boolean; wrap?: boolean };

/**
 * Right-side detail Sheet: a fixed header, a scrollable key/value + content body, and an
 * optional pinned footer for primary actions (always visible, never cropped).
 *
 * Layout note: a Radix ScrollArea is deliberately NOT used — its viewport is display:table,
 * which sizes to content and defeats truncate/min-w-0 (long values overflow horizontally). A
 * plain flex column + overflow-y-auto body respects width and keeps the footer on-screen.
 */
export function InfoSheet({
  open, onOpenChange, title, sub, badge, fields, children, footer,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  sub?: string;
  badge?: React.ReactNode;
  fields: Field[];
  children?: React.ReactNode;
  footer?: React.ReactNode;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="flex h-dvh w-full flex-col gap-0 p-0 sm:max-w-md">
        <SheetHeader className="shrink-0 border-b pr-12">
          {sub && <SheetDescription className="font-mono text-[10px] uppercase tracking-[0.2em]">{sub}</SheetDescription>}
          <SheetTitle className="font-mono text-base leading-snug break-words">{title}</SheetTitle>
          {badge && <div className="pt-1">{badge}</div>}
        </SheetHeader>

        <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden overscroll-contain">
          <dl className="divide-y">
            {fields.filter((f) => f.value !== undefined && f.value !== null && f.value !== "").map((f, i) => (
              <div key={i} className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-3 px-4 py-2.5 text-sm sm:grid-cols-[7.5rem_minmax(0,1fr)] sm:px-5">
                <dt className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">{f.label}</dt>
                <dd className={`min-w-0 ${f.mono ? "font-mono text-xs" : ""} ${f.wrap ? "break-words" : "truncate"}`}>{f.value}</dd>
              </div>
            ))}
          </dl>
          {children && (<><Separator /><div className="p-4 sm:p-5">{children}</div></>)}
        </div>

        {footer && (
          <div className="shrink-0 border-t bg-background/95 p-4 backdrop-blur supports-[backdrop-filter]:bg-background/80">
            {footer}
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

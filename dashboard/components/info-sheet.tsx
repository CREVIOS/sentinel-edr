"use client";

import * as React from "react";
import {
  Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";

export type Field = { label: string; value: React.ReactNode; mono?: boolean; wrap?: boolean };

/** Right-side detail Sheet with a centralized key/value layout for in-depth records. */
export function InfoSheet({
  open, onOpenChange, title, sub, badge, fields, children,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  sub?: string;
  badge?: React.ReactNode;
  fields: Field[];
  children?: React.ReactNode;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full gap-0 p-0 sm:max-w-md">
        <SheetHeader className="border-b">
          {sub && <SheetDescription className="font-mono text-[10px] uppercase tracking-[0.2em]">{sub}</SheetDescription>}
          <SheetTitle className="font-mono text-base leading-snug">{title}</SheetTitle>
          {badge && <div className="pt-1">{badge}</div>}
        </SheetHeader>
        <ScrollArea className="h-[calc(100dvh-6rem)]">
          <dl className="divide-y">
            {fields.filter((f) => f.value !== undefined && f.value !== null && f.value !== "").map((f, i) => (
              <div key={i} className="grid grid-cols-[7.5rem_1fr] gap-3 px-5 py-2.5 text-sm">
                <dt className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">{f.label}</dt>
                <dd className={`${f.mono ? "font-mono text-xs" : ""} ${f.wrap ? "break-words" : "truncate"}`}>{f.value}</dd>
              </div>
            ))}
          </dl>
          {children && (<><Separator /><div className="p-5">{children}</div></>)}
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}

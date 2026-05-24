"use client";

import { useId } from "react";
import { Area, AreaChart, ResponsiveContainer } from "recharts";

/** Compact realtime area sparkline with a gradient fill — for metric cards. */
export function Sparkline({
  data,
  color = "var(--primary)",
  height = 38,
}: {
  data: number[];
  color?: string;
  height?: number;
}) {
  const id = useId().replace(/:/g, "");
  const d = data.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={d} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id={`sp-${id}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.4} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area
          type="monotone"
          dataKey="v"
          stroke={color}
          strokeWidth={1.75}
          fill={`url(#sp-${id})`}
          isAnimationActive
          animationDuration={500}
          dot={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

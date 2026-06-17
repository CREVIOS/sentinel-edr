// Investigation aid: reconstruct a process tree from the event stream by linking pid → ppid,
// so an analyst can trace a detection back to patient-zero and expand into children with one
// click. Falls back to the agent-provided `lineage` string when the live event set is too
// sparse to build a real graph.
import { useMemo, useState } from "react";
import type { Event } from "./types";

function ProcNode({
  e,
  depth,
  focal,
  onClick,
}: {
  e: Event;
  depth: number;
  focal: boolean;
  onClick: (e: Event) => void;
}) {
  const p = e.process!;
  return (
    <div
      className={`proc-node${focal ? " focal" : ""}`}
      style={{ paddingLeft: 6 + depth * 18 }}
      onClick={() => onClick(e)}
      title={p.cmdline || p.exe || ""}
    >
      {depth > 0 && <span className="proc-branch">└─</span>}
      <span className="proc-name">{p.name || p.exe?.split("/").pop() || "?"}</span>
      <span className="proc-pid mono dim">#{p.pid}</span>
      {p.user && <span className="chip">{p.user}</span>}
      {p.cmdline && <span className="proc-cmd mono dim">{p.cmdline}</span>}
    </div>
  );
}

export function ProcessTree({ event, events }: { event: Event; events: Event[] }) {
  const [focus, setFocus] = useState<Event>(event);

  // pid → best process event on the same host (prefer one carrying a cmdline).
  const byPid = useMemo(() => {
    const m = new Map<number, Event>();
    for (const e of events) {
      const p = e.process;
      if (!p?.pid) continue;
      if (event.hostname && e.hostname !== event.hostname) continue;
      const cur = m.get(p.pid);
      if (!cur || (!cur.process?.cmdline && p.cmdline)) m.set(p.pid, e);
    }
    if (focus.process?.pid) m.set(focus.process.pid, focus);
    if (event.process?.pid && !m.has(event.process.pid)) m.set(event.process.pid, event);
    return m;
  }, [events, event, focus]);

  const focalPid = focus.process?.pid;

  // ancestry: walk ppid links upward to the earliest known parent.
  const ancestry = useMemo(() => {
    const chain: Event[] = [];
    const seen = new Set<number>();
    let cur: Event | undefined = focalPid ? byPid.get(focalPid) : undefined;
    while (cur?.process?.pid && !seen.has(cur.process.pid)) {
      seen.add(cur.process.pid);
      chain.unshift(cur);
      const pp = cur.process.ppid;
      cur = pp ? byPid.get(pp) : undefined;
    }
    return chain;
  }, [byPid, focalPid]);

  const children = useMemo(() => {
    if (!focalPid) return [];
    return [...byPid.values()].filter((e) => e.process?.ppid === focalPid && e.process?.pid !== focalPid);
  }, [byPid, focalPid]);

  const hasGraph = ancestry.length > 1 || children.length > 0;
  const lineage = focus.process?.lineage;

  if (!focus.process?.pid) return null;

  return (
    <div className="proc-tree-wrap">
      <div className="proc-tree-head">
        <span className="page-kicker">Process Tree</span>
        {focus.process?.pid !== event.process?.pid && (
          <button className="btn btn-ghost btn-sm" onClick={() => setFocus(event)}>↩ reset focus</button>
        )}
      </div>

      {hasGraph ? (
        <div className="proc-tree">
          {ancestry.map((e, i) => (
            <ProcNode key={`a-${e.process!.pid}`} e={e} depth={i} focal={e.process!.pid === focalPid} onClick={setFocus} />
          ))}
          {children.map((e) => (
            <ProcNode key={`c-${e.process!.pid}`} e={e} depth={ancestry.length} focal={false} onClick={setFocus} />
          ))}
        </div>
      ) : lineage ? (
        <div className="proc-lineage mono">{lineage}</div>
      ) : (
        <div className="dim" style={{ fontSize: 12 }}>
          single process observed (no parent/child events in the live window)
        </div>
      )}
      {hasGraph && (
        <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>click a process to re-focus the tree · {byPid.size} processes in window</div>
      )}
    </div>
  );
}

"use client";

import { useCallback, useMemo } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge,
  Handle,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Bug,
  FileText,
  Globe,
  Cpu,
  Server,
  User,
  Waypoints,
  Boxes,
} from "lucide-react";
import type { AttackGraph as AttackGraphType, GraphNode } from "@/lib/types";
import { NODE_COLOR, NODE_LABEL, PHASE_COLOR, PHASE_LABEL } from "@/lib/theme";

const ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  user: User,
  host: Server,
  process: Cpu,
  file: FileText,
  ip: Globe,
  domain: Waypoints,
  ioc: Bug,
  service: Boxes,
};

interface NodeData extends Record<string, unknown> {
  node: GraphNode;
  onCritical: boolean;
  selected: boolean;
}

function EntityNode({ data }: NodeProps<Node<NodeData>>) {
  const { node, onCritical } = data;
  const color = NODE_COLOR[node.type] ?? "#22d3ee";
  const Icon = ICON[node.type] ?? Boxes;
  const risky = node.risk >= 60;
  return (
    <div
      className="group relative flex items-center gap-2 rounded-lg px-3 py-2 transition"
      style={{
        minWidth: 130,
        maxWidth: 190,
        background: "var(--panel-2)",
        border: `1.5px solid ${risky ? color : "var(--border)"}`,
        boxShadow: onCritical
          ? `0 0 0 1.5px ${color}, 0 0 18px -4px ${color}`
          : risky
            ? `0 0 14px -6px ${color}`
            : "none",
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color, width: 6, height: 6, border: "none" }} />
      <div
        className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md"
        style={{ background: `${color}1c`, color }}
      >
        <Icon className="h-3.5 w-3.5" />
      </div>
      <div className="min-w-0 leading-tight">
        <div className="truncate text-[11px] font-medium text-[var(--fg)]" title={node.label}>
          {node.label}
        </div>
        <div className="mono text-[9px] uppercase tracking-wide" style={{ color }}>
          {NODE_LABEL[node.type] ?? node.type}
          {node.risk > 0 && <span className="text-[var(--fg-dim)]"> · {Math.round(node.risk)}</span>}
        </div>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: color, width: 6, height: 6, border: "none" }} />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

export function AttackGraph({
  graph,
  criticalPath,
  onSelect,
  selectedId,
}: {
  graph: AttackGraphType;
  criticalPath: string[];
  onSelect: (n: GraphNode | null) => void;
  selectedId?: string | null;
}) {
  const critical = useMemo(() => new Set(criticalPath), [criticalPath]);

  const { nodes, edges } = useMemo(() => {
    // group by layer, stack vertically
    const byLayer = new Map<number, GraphNode[]>();
    for (const n of graph.nodes) {
      const arr = byLayer.get(n.layer) ?? [];
      arr.push(n);
      byLayer.set(n.layer, arr);
    }
    const COL_W = 240;
    const ROW_H = 78;
    const rfNodes: Node<NodeData>[] = [];
    for (const [layer, group] of [...byLayer.entries()].sort((a, b) => a[0] - b[0])) {
      const totalH = group.length * ROW_H;
      group.forEach((n, i) => {
        rfNodes.push({
          id: n.id,
          type: "entity",
          position: { x: layer * COL_W, y: i * ROW_H - totalH / 2 + 400 },
          data: { node: n, onCritical: critical.has(n.id), selected: selectedId === n.id },
          draggable: true,
        });
      });
    }
    const rfEdges: Edge[] = graph.edges.map((e) => {
      const color = e.phase ? PHASE_COLOR[e.phase] ?? "#5c6b80" : "#5c6b80";
      const onCrit = critical.has(e.source) && critical.has(e.target);
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.relation.replace(/_/g, " "),
        animated: onCrit,
        style: { stroke: color, strokeWidth: onCrit ? 2.4 : 1.4, opacity: onCrit ? 1 : 0.5 },
        labelStyle: { fill: "#8a99ad", fontSize: 9, fontFamily: "var(--font-mono)" },
        labelBgStyle: { fill: "#0c131c", fillOpacity: 0.85 },
        markerEnd: { type: "arrowclosed", color } as unknown as Edge["markerEnd"],
      };
    });
    return { nodes: rfNodes, edges: rfEdges };
  }, [graph, critical, selectedId]);

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node<NodeData>) => onSelect(node.data.node),
    [onSelect],
  );

  const phasesUsed = useMemo(() => {
    const s = new Set<string>();
    graph.edges.forEach((e) => e.phase && s.add(e.phase));
    return [...s];
  }, [graph.edges]);

  return (
    <div className="relative h-[560px] w-full overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--bg)]">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        onPaneClick={() => onSelect(null)}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.2}
        maxZoom={1.8}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#1b2634" />
        <Controls showInteractive={false} position="bottom-right" />
      </ReactFlow>

      {/* Phase legend */}
      <div className="pointer-events-none absolute left-3 top-3 flex max-w-[70%] flex-wrap gap-1.5">
        {phasesUsed.map((p) => (
          <span
            key={p}
            className="mono rounded px-1.5 py-0.5 text-[9px]"
            style={{
              color: PHASE_COLOR[p],
              background: `${PHASE_COLOR[p]}18`,
              border: `1px solid ${PHASE_COLOR[p]}44`,
            }}
          >
            {PHASE_LABEL[p] ?? p}
          </span>
        ))}
      </div>
    </div>
  );
}

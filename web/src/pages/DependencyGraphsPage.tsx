import * as d3 from 'd3'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { DependencyGraph, DependencyGraphRoot } from '../lib/api/index.ts'
import { normalizeGraph, normalizeGraphRoots, useDependencyGraph, useDependencyGraphRoots } from '../features/dependency-graphs/api.ts'
import { QueryStateNotice, SummaryMetrics } from '../features/evaluations/components.tsx'
import { useTenant } from '../features/tenant/useTenant.ts'
import { graphClass } from '../features/dependency-graphs/styles.ts'

type GraphNode = NonNullable<DependencyGraph['nodes']>[number]
type GraphEdge = NonNullable<DependencyGraph['edges']>[number]
type GraphSelection = { kind: 'node'; id: string } | { kind: 'edge'; id: string } | null
type D3GraphNode = GraphNode & d3.SimulationNodeDatum
type D3GraphLink = d3.SimulationLinkDatum<D3GraphNode> & { id: string; dependencyType: string }

const dependencyTypes = ['prod', 'dev', 'peer', 'optional'] as const
const graphWidth = 1120
const graphHeight = 650

function packageName(node: GraphNode) {
  return node.artifact.namespace ? `${node.artifact.namespace}/${node.artifact.name}` : node.artifact.name
}

function rootName(root: DependencyGraphRoot) {
  return `${root.package_name}@${root.version}`
}

function dateLabel(value: string | null | undefined) {
  return value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Not resolved yet'
}

function statusClass(status: string) {
  return graphClass(status === 'complete' ? 'graph-status-complete' : status === 'failed' ? 'graph-status-failed' : 'graph-status-pending')
}

function nodeKind(node: GraphNode) {
  return node.min_depth === 0 ? 'root' : node.min_depth === 1 ? 'direct' : 'transitive'
}

function nodeRadius(node: GraphNode) {
  return nodeKind(node) === 'root' ? 27 : nodeKind(node) === 'direct' ? 23 : 20
}

function lineEndpoint(link: D3GraphLink, side: 'source' | 'target') {
  const source = link.source as D3GraphNode
  const target = link.target as D3GraphNode
  const sourceX = source.x ?? graphWidth / 2
  const sourceY = source.y ?? graphHeight / 2
  const targetX = target.x ?? graphWidth / 2
  const targetY = target.y ?? graphHeight / 2
  const distance = Math.hypot(targetX - sourceX, targetY - sourceY) || 1
  const node = side === 'source' ? source : target
  const x = side === 'source' ? sourceX : targetX
  const y = side === 'source' ? sourceY : targetY
  const direction = side === 'source' ? 1 : -1
  const radius = nodeRadius(node)
  return {
    x: x + direction * ((targetX - sourceX) / distance) * radius,
    y: y + direction * ((targetY - sourceY) / distance) * radius,
  }
}

function truncate(value: string, length: number) {
  return value.length > length ? `${value.slice(0, length - 1)}...` : value
}

function GraphMap({ nodes, edges, selection, onSelect }: { nodes: GraphNode[]; edges: GraphEdge[]; selection: GraphSelection; onSelect: (selection: GraphSelection) => void }) {
  const svgRef = useRef<SVGSVGElement>(null)
  const svgSelectionRef = useRef<d3.Selection<SVGSVGElement, unknown, null, undefined> | null>(null)
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null)
  const [zoomLevel, setZoomLevel] = useState(1)

  useEffect(() => {
    if (!svgRef.current) return

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svgSelectionRef.current = svg

    const d3Nodes: D3GraphNode[] = nodes.map((node) => ({ ...node }))
    const d3Links: D3GraphLink[] = edges.map((edge) => ({
      id: edge.id,
      dependencyType: edge.dependency_type,
      source: edge.parent_node_id,
      target: edge.child_node_id,
    }))
    svg.append('rect')
      .attr('class', graphClass('graph-map-background'))
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('rx', 20)
      .attr('pointer-events', 'none')
    const container = svg.append('g')
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.65, 2.5])
      .on('zoom', (event) => {
        container.attr('transform', event.transform)
        setZoomLevel(event.transform.k)
      })
    zoomRef.current = zoom
    svg.call(zoom).on('dblclick.zoom', null)
    svg.on('click.graph-selection', () => onSelect(null))

    const simulation = d3.forceSimulation<D3GraphNode>(d3Nodes)
      .force('link', d3.forceLink<D3GraphNode, D3GraphLink>(d3Links).id((node) => node.id).distance(150).strength(0.8))
      .force('charge', d3.forceManyBody<D3GraphNode>().strength(-300))
      .force('center', d3.forceCenter(graphWidth / 2, graphHeight / 2))
      .force('collision', d3.forceCollide<D3GraphNode>().radius((node) => nodeRadius(node) + 21))

    const linkGroup = container.append('g').attr('class', graphClass('graph-edges'))
    const links = linkGroup.selectAll<SVGGElement, D3GraphLink>('g')
      .data(d3Links, (link) => link.id)
      .join('g')
      .attr('class', graphClass('graph-edge-group'))
      .attr('data-graph-edge', 'true')
      .attr('data-edge-id', (link) => link.id)
      .on('click', (event, link) => {
        event.stopPropagation()
        onSelect({ kind: 'edge', id: link.id })
      })
      .on('keydown', (event, link) => {
        if (event.key === 'Enter' || event.key === ' ') onSelect({ kind: 'edge', id: link.id })
      })
      .attr('tabindex', 0)

    links.append('line').attr('class', graphClass('graph-edge-hit-area'))
    links.append('line').attr('class', graphClass('graph-edge'))

    const nodeGroup = container.append('g').attr('class', graphClass('graph-nodes'))
    const node = nodeGroup.selectAll<SVGGElement, D3GraphNode>('g')
      .data(d3Nodes, (item) => item.id)
      .join('g')
      .attr('class', (item) => graphClass('graph-node', `graph-node-${nodeKind(item)}`))
      .attr('data-graph-node', 'true')
      .attr('data-node-id', (item) => item.id)
      .attr('tabindex', 0)
      .on('click', (event, item) => {
        if (event.defaultPrevented) return
        event.stopPropagation()
        onSelect({ kind: 'node', id: item.id })
      })
      .on('keydown', (event, item) => {
        if (event.key === 'Enter' || event.key === ' ') onSelect({ kind: 'node', id: item.id })
      })
      .call(d3.drag<SVGGElement, D3GraphNode>()
        .on('start', (event, item) => {
          if (!event.active) simulation.alphaTarget(0.25).restart()
          item.fx = item.x
          item.fy = item.y
        })
        .on('drag', (event, item) => {
          item.fx = event.x
          item.fy = event.y
        })
        .on('end', (event, item) => {
          if (!event.active) simulation.alphaTarget(0)
          item.fx = null
          item.fy = null
        }))

    node.append('title').text((item) => `${packageName(item)}@${item.artifact.version} | ${nodeKind(item)} dependency | depth ${item.min_depth}`)
    node.append('circle')
      .attr('class', graphClass('graph-node-circle'))
      .attr('r', nodeRadius)
    node.append('text')
      .attr('class', graphClass('graph-node-depth'))
      .attr('text-anchor', 'middle')
      .attr('y', 4)
      .text((item) => nodeKind(item) === 'root' ? 'R' : `D${item.min_depth}`)
    node.append('text')
      .attr('class', graphClass('graph-node-name'))
      .attr('x', (item) => (nodeKind(item) === 'root' ? 39 : 35))
      .attr('y', -4)
      .text((item) => truncate(packageName(item), 26))
    node.append('text')
      .attr('class', graphClass('graph-node-version'))
      .attr('x', (item) => (nodeKind(item) === 'root' ? 39 : 35))
      .attr('y', 14)
      .text((item) => item.artifact.version)
    node.append('text')
      .attr('class', graphClass('graph-node-kind'))
      .attr('x', (item) => (nodeKind(item) === 'root' ? 39 : 35))
      .attr('y', 30)
      .text((item) => `${nodeKind(item)} · ${(item.dependency_types ?? []).join(', ') || 'prod'}`)

    simulation.on('tick', () => {
      links.selectAll<SVGLineElement, D3GraphLink>('line')
        .attr('x1', (link) => lineEndpoint(link, 'source').x)
        .attr('y1', (link) => lineEndpoint(link, 'source').y)
        .attr('x2', (link) => lineEndpoint(link, 'target').x)
        .attr('y2', (link) => lineEndpoint(link, 'target').y)
      node.attr('transform', (item) => `translate(${item.x ?? graphWidth / 2},${item.y ?? graphHeight / 2})`)
    })

    return () => {
      simulation.stop()
      svg.on('.zoom', null)
      svg.on('.graph-selection', null)
      svgSelectionRef.current = null
      zoomRef.current = null
    }
  }, [edges, nodes, onSelect])

  useEffect(() => {
    if (!svgRef.current) return
    const selectedDependency = selection?.kind === 'edge' ? edges.find((edge) => edge.id === selection.id) : null
    const selectedNode = selection?.kind === 'node' ? selection.id : null
    const relatedNodeIds = new Set<string>()
    const relatedEdgeIds = new Set<string>()
    if (selectedDependency) {
      relatedNodeIds.add(selectedDependency.parent_node_id)
      relatedNodeIds.add(selectedDependency.child_node_id)
      let expanded = true
      while (expanded) {
        expanded = false
        edges.forEach((edge) => {
          if (relatedNodeIds.has(edge.parent_node_id) && !relatedNodeIds.has(edge.child_node_id)) {
            relatedNodeIds.add(edge.child_node_id)
            expanded = true
          }
          if (relatedNodeIds.has(edge.parent_node_id) && relatedNodeIds.has(edge.child_node_id)) relatedEdgeIds.add(edge.id)
        })
      }
    } else if (selectedNode) {
      relatedNodeIds.add(selectedNode)
      edges.forEach((edge) => {
        if (edge.parent_node_id === selectedNode || edge.child_node_id === selectedNode) {
          relatedEdgeIds.add(edge.id)
          relatedNodeIds.add(edge.parent_node_id)
          relatedNodeIds.add(edge.child_node_id)
        }
      })
    }
    d3.select(svgRef.current).selectAll<SVGGElement, D3GraphNode>(`.${graphClass('graph-node')}`)
      .classed(graphClass('graph-node-selected'), (node) => selection?.kind === 'node' && selection.id === node.id)
      .classed(graphClass('graph-node-related'), (node) => relatedNodeIds.has(node.id))
      .attr('data-selected', (node) => String(selection?.kind === 'node' && selection.id === node.id))
      .attr('data-related', (node) => String(relatedNodeIds.has(node.id)))
    d3.select(svgRef.current).selectAll<SVGGElement, D3GraphLink>(`.${graphClass('graph-edge-group')}`)
      .classed(graphClass('graph-edge-selected'), (edge) => selection?.kind === 'edge' && selection.id === edge.id)
      .classed(graphClass('graph-edge-related'), (edge) => relatedEdgeIds.has(edge.id))
      .attr('data-selected', (edge) => String(selection?.kind === 'edge' && selection.id === edge.id))
      .attr('data-related', (edge) => String(relatedEdgeIds.has(edge.id)))
  }, [edges, selection])

  function zoomBy(factor: number) {
    if (svgSelectionRef.current && zoomRef.current) {
      svgSelectionRef.current.transition().duration(180).call(zoomRef.current.scaleBy, factor)
    }
  }

  function resetZoom() {
    if (svgSelectionRef.current && zoomRef.current) {
      svgSelectionRef.current.transition().duration(180).call(zoomRef.current.transform, d3.zoomIdentity)
    }
  }

  return <div className={graphClass("graph-map-stage")}><div className={graphClass("graph-zoom-controls")} role="group" aria-label="Graph zoom controls"><button aria-label="Zoom out" disabled={zoomLevel <= 0.65} onClick={() => zoomBy(0.75)} type="button">-</button><span>{Math.round(zoomLevel * 100)}%</span><button aria-label="Zoom in" disabled={zoomLevel >= 2.5} onClick={() => zoomBy(1.25)} type="button">+</button><button aria-label="Reset graph zoom" onClick={resetZoom} type="button">Reset</button></div><div className={graphClass("graph-map-info")}><button aria-label="Show graph instructions" type="button">i</button><div className={graphClass("graph-map-info-tooltip")} role="tooltip">Drag circles to rearrange the graph. Click a circle or line to inspect its details. Use the controls or trackpad to zoom.</div></div><div className={graphClass("graph-map-scroll")}><svg ref={svgRef} className={graphClass("graph-map")} role="img" aria-label="Interactive dependency graph" viewBox={`0 0 ${graphWidth} ${graphHeight}`} /></div></div>
}

function GraphWorkspace({ graph }: { graph: DependencyGraph }) {
  const [search, setSearch] = useState('')
  const [activeTypes, setActiveTypes] = useState<string[]>([])
  const [maxDepth, setMaxDepth] = useState<number | null>(3)
  const [selection, setSelection] = useState<GraphSelection>(null)
  const nodes = useMemo(() => (graph.nodes ?? []) as GraphNode[], [graph.nodes])
  const edges = useMemo(() => (graph.edges ?? []) as GraphEdge[], [graph.edges])
  const visibleNodes = useMemo(() => nodes.filter((node) => {
    const text = `${packageName(node)} ${node.artifact.version}`.toLowerCase()
    return (!search.trim() || text.includes(search.trim().toLowerCase())) &&
      (activeTypes.length === 0 || activeTypes.some((type) => (node.dependency_types ?? []).includes(type))) &&
      (maxDepth === null || node.min_depth <= maxDepth)
  }), [activeTypes, maxDepth, nodes, search])
  const visibleEdges = useMemo(() => {
    const visibleIds = new Set(visibleNodes.map((node) => node.id))
    return edges.filter((edge) => visibleIds.has(edge.parent_node_id) && visibleIds.has(edge.child_node_id))
  }, [edges, visibleNodes])
  const selectedNode = selection?.kind === 'node' ? nodes.find((node) => node.id === selection.id) ?? null : null
  const selectedEdge = selection?.kind === 'edge' ? edges.find((edge) => edge.id === selection.id) ?? null : null
  const nodesById = new Map(nodes.map((node) => [node.id, node]))

  return <><div className={graphClass("graph-toolbar")}><label className={graphClass("graph-search")}><span>Find a package</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search name or version" /></label><label className={graphClass("graph-depth-filter")}><span>Show through depth</span><select value={maxDepth ?? 'all'} onChange={(event) => setMaxDepth(event.target.value === 'all' ? null : Number(event.target.value))}><option value="all">All depths</option><option value="1">Root + direct</option><option value="2">Through depth 2</option><option value="3">Through depth 3</option><option value="4">Through depth 4</option></select></label><div className={graphClass("graph-type-filters")} role="group" aria-label="Dependency types">{dependencyTypes.map((type) => <button className={graphClass(activeTypes.includes(type) && 'graph-type-active')} key={type} onClick={() => setActiveTypes((current) => current.includes(type) ? current.filter((value) => value !== type) : [...current, type])} type="button">{type}</button>)}</div></div><div className={graphClass("graph-legend")}><span><i className={graphClass("graph-legend-dot graph-legend-root")} />Root package</span><span><i className={graphClass("graph-legend-dot graph-legend-direct")} />Direct dependency</span><span><i className={graphClass("graph-legend-dot graph-legend-transitive")} />Transitive dependency</span><span><i className={graphClass("graph-legend-line")} />Click a line for relationship details</span></div><div className={graphClass('graph-workspace-grid', !(selectedNode || selectedEdge) && 'graph-workspace-grid-full')}><section className={graphClass("graph-map-card")} aria-label="Dependency relationship map">{visibleNodes.length ? <GraphMap nodes={visibleNodes} edges={visibleEdges} selection={selection} onSelect={setSelection} /> : <QueryStateNotice title="No matching packages" message="Adjust the search, depth, or dependency type filters." />}</section>{(selectedNode || selectedEdge) && <aside className={graphClass("card graph-detail-card")}><p className={graphClass("eyebrow")}>{selectedEdge ? 'Selected relationship' : 'Selected package'}</p>{selectedNode ? <><h3>{packageName(selectedNode)}</h3><p className={graphClass("graph-detail-version")}>{selectedNode.artifact.version}</p><dl className={graphClass("graph-detail-list")}><div><dt>Role</dt><dd>{nodeKind(selectedNode)}</dd></div><div><dt>Depth</dt><dd>{selectedNode.min_depth === 0 ? 'Root' : selectedNode.min_depth}</dd></div><div><dt>Declared as</dt><dd>{(selectedNode.dependency_types ?? []).join(', ') || 'prod'}</dd></div><div><dt>Incoming links</dt><dd>{edges.filter((edge) => edge.child_node_id === selectedNode.id).length}</dd></div><div><dt>Outgoing links</dt><dd>{edges.filter((edge) => edge.parent_node_id === selectedNode.id).length}</dd></div></dl></> : selectedEdge ? <><h3>{packageName(nodesById.get(selectedEdge.parent_node_id) ?? nodes[0])}</h3><p className={graphClass("muted graph-detail-arrow")}>depends on</p><h3>{packageName(nodesById.get(selectedEdge.child_node_id) ?? nodes[0])}</h3><dl className={graphClass("graph-detail-list")}><div><dt>Dependency type</dt><dd>{selectedEdge.dependency_type}</dd></div><div><dt>Relationship</dt><dd>Parent to child</dd></div></dl></> : null}</aside>}</div></>
}

export function DependencyGraphsPage() {
  const { tenantId } = useTenant()
  const rootsQuery = useDependencyGraphRoots()
  const roots = useMemo(() => normalizeGraphRoots(rootsQuery.data), [rootsQuery.data])
  const [selectedRootId, setSelectedRootId] = useState<string | null>(null)
  const activeRootId = selectedRootId && roots.some((root) => root.id === selectedRootId) ? selectedRootId : roots[0]?.id ?? null
  const graphQuery = useDependencyGraph(activeRootId)
  const graph = normalizeGraph(graphQuery.data)
  const completeCount = roots.filter((root) => root.status === 'complete').length

  return <section className={graphClass("page dependency-graphs-page")}><header className={graphClass("page-header")}><div><p className={graphClass("eyebrow")}>Resolved supply chain</p><h2>Dependency graphs</h2><p className={graphClass("page-summary")}>Explore package relationships as a living graph. Drag nodes, inspect edges, and follow direct dependencies into their transitive supply chain.</p></div><div className={graphClass("page-actions")}><span className={graphClass("status-pill")}>{tenantId ? `${roots.length} roots` : 'Select a tenant'}</span><button className={graphClass("secondary-button")} onClick={() => void rootsQuery.refetch()} type="button">Refresh</button></div></header>{rootsQuery.isPending ? <QueryStateNotice title="Loading dependency graphs" message="Fetching resolved npm graphs for this tenant." /> : rootsQuery.isError ? <QueryStateNotice title="Unable to load dependency graphs" message="The graph inventory is unavailable right now." onAction={() => void rootsQuery.refetch()} /> : roots.length === 0 ? <QueryStateNotice title="No resolved graphs yet" message="Graphs appear here after the proxy resolves an npm install snapshot." /> : <><SummaryMetrics items={[{ label: 'Resolved roots', value: String(completeCount), hint: `of ${roots.length} tracked` }, { label: 'Packages in view', value: String(graph?.nodes?.length ?? 0), hint: 'Selected graph' }, { label: 'Relationships', value: String(graph?.edges?.length ?? 0), hint: 'Selected graph' }]} /><div className={graphClass("dependency-graphs-layout")}><aside className={graphClass("card graph-root-list")}><div className={graphClass("section-header")}><div><h3>Install roots</h3><p className={graphClass("muted")}>Select a lockfile root to explore.</p></div></div><div className={graphClass("graph-root-items")}>{roots.map((root) => <button className={graphClass('graph-root-item', root.id === activeRootId && 'graph-root-item-active')} key={root.id} onClick={() => setSelectedRootId(root.id)} type="button"><span className={graphClass("graph-root-name")}>{rootName(root)}</span><span className={graphClass("graph-root-meta")}><span className={statusClass(root.status)}>{root.status}</span><span>{dateLabel(root.resolved_at)}</span></span></button>)}</div></aside><main className={graphClass("graph-main")}>{graphQuery.isPending ? <QueryStateNotice title="Loading graph" message="Building the relationship map." /> : graphQuery.isError || !graph ? <QueryStateNotice title="Graph unavailable" message="This graph could not be loaded." onAction={() => void graphQuery.refetch()} /> : <><div className={graphClass("card graph-heading")}><div><p className={graphClass("eyebrow")}>{graph.root.upstream_id}</p><h3>{rootName(graph.root)}</h3><p className={graphClass("muted")}>Resolved {dateLabel(graph.root.resolved_at)} · hash {graph.root.graph_hash?.slice(0, 12) || 'pending'}</p></div><span className={statusClass(graph.root.status)}>{graph.root.status}</span></div><GraphWorkspace graph={graph} /></>}</main></div></>}</section>
}

import React, { useState, useMemo, useCallback } from "react";
import { useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";

interface DomainResult {
  domain: {
    id: number;
    domainName: string;
    tld: string;
    birthYear: number | null;
  };
  metrics: {
    backlinksCount: number;
    trustFlow: number;
    citationFlow: number;
    domainAuthority: number;
    pageAuthority: number;
    qualityScore: number;
  };
}

interface DomainNetworkGraphProps {
  domains: DomainResult[];
}

export function DomainNetworkGraph({ domains }: DomainNetworkGraphProps) {
  const [, setLocation] = useLocation();
  const [hoveredDomain, setHoveredDomain] = useState<DomainResult | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Calculate positions using a force-directed-like layout
  const nodePositions = useMemo(() => {
    const positions: { x: number; y: number; radius: number }[] = [];
    const width = 900;
    const height = 600;
    const centerX = width / 2;
    const centerY = height / 2;
    
    // Sort by quality score to place best domains closer to center
    const sortedDomains = [...domains].sort((a, b) => b.metrics.qualityScore - a.metrics.qualityScore);
    
    sortedDomains.forEach((domain, index) => {
      const qualityScore = domain.metrics.qualityScore;
      
      // Calculate radius based on quality - higher quality = closer to center
      const maxRadius = Math.min(width, height) / 2 - 60;
      const minRadius = 80;
      const radiusFromCenter = minRadius + (100 - qualityScore) / 100 * (maxRadius - minRadius);
      
      // Distribute nodes in a spiral pattern
      const goldenAngle = Math.PI * (3 - Math.sqrt(5)); // Golden angle for even distribution
      const angle = index * goldenAngle;
      
      // Add some randomness for natural look
      const jitterX = (Math.random() - 0.5) * 30;
      const jitterY = (Math.random() - 0.5) * 30;
      
      const x = centerX + Math.cos(angle) * radiusFromCenter + jitterX;
      const y = centerY + Math.sin(angle) * radiusFromCenter + jitterY;
      
      // Node size based on quality score
      const nodeRadius = 4 + (qualityScore / 100) * 8;
      
      positions.push({ x, y, radius: nodeRadius });
    });
    
    return positions;
  }, [domains]);

  // Get node style based on quality score
  const getNodeStyle = useCallback((score: number) => {
    if (score >= 75) return { fill: "#18181b", stroke: "#18181b", strokeWidth: 2 }; // Excellent - solid black
    if (score >= 60) return { fill: "#52525b", stroke: "#52525b", strokeWidth: 1.5 }; // Good - dark gray
    if (score >= 45) return { fill: "transparent", stroke: "#71717a", strokeWidth: 1.5 }; // Fair - hollow gray
    return { fill: "transparent", stroke: "#a1a1aa", strokeWidth: 1 }; // Poor - light gray hollow
  }, []);

  const handleNodeClick = useCallback((domain: DomainResult) => {
    setLocation(`/domain/${domain.domain.id}`);
  }, [setLocation]);

  const handleMouseMove = useCallback((e: React.MouseEvent, domain: DomainResult) => {
    setHoveredDomain(domain);
    const rect = e.currentTarget.closest('svg')?.getBoundingClientRect();
    if (rect) {
      setTooltipPos({ 
        x: e.clientX - rect.left, 
        y: e.clientY - rect.top 
      });
    }
  }, []);

  // Sort domains by quality for rendering (lower quality first so high quality renders on top)
  const sortedDomains = useMemo(() => 
    [...domains].sort((a, b) => a.metrics.qualityScore - b.metrics.qualityScore),
    [domains]
  );

  return (
    <div className="relative w-full bg-white dark:bg-zinc-900 overflow-hidden">
      {/* Grid Background */}
      <div 
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: `
            linear-gradient(to right, #f4f4f5 1px, transparent 1px),
            linear-gradient(to bottom, #f4f4f5 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px'
        }}
      />

      <svg 
        width="100%" 
        height="600" 
        viewBox="0 0 900 600" 
        preserveAspectRatio="xMidYMid meet"
        className="relative"
      >
        {/* Central hub node */}
        <g>
          <circle cx="450" cy="300" r="20" fill="#18181b" />
          <circle cx="450" cy="300" r="30" fill="none" stroke="#18181b" strokeWidth="1" strokeDasharray="4 4" />
          <text x="450" y="355" textAnchor="middle" className="text-[10px] fill-zinc-500 font-medium">
            ROOT
          </text>
        </g>

        {/* Connection lines from center to nodes */}
        {sortedDomains.map((domain, index) => {
          const originalIndex = domains.findIndex(d => d.domain.id === domain.domain.id);
          const pos = nodePositions[originalIndex];
          if (!pos) return null;
          
          const style = getNodeStyle(domain.metrics.qualityScore);
          
          return (
            <line
              key={`line-${domain.domain.id}`}
              x1={450}
              y1={300}
              x2={pos.x}
              y2={pos.y}
              stroke="#e4e4e7"
              strokeWidth="1"
              className="dark:stroke-zinc-800"
            />
          );
        })}

        {/* Domain nodes */}
        {sortedDomains.map((domain, index) => {
          const originalIndex = domains.findIndex(d => d.domain.id === domain.domain.id);
          const pos = nodePositions[originalIndex];
          if (!pos) return null;
          
          const style = getNodeStyle(domain.metrics.qualityScore);
          const isHovered = hoveredDomain?.domain.id === domain.domain.id;
          
          return (
            <g
              key={domain.domain.id}
              transform={`translate(${pos.x}, ${pos.y})`}
              style={{ cursor: "pointer" }}
              onClick={() => handleNodeClick(domain)}
              onMouseEnter={(e) => handleMouseMove(e, domain)}
              onMouseLeave={() => setHoveredDomain(null)}
              onMouseMove={(e) => handleMouseMove(e, domain)}
            >
              {/* Hover ring */}
              {isHovered && (
                <circle
                  cx="0"
                  cy="0"
                  r={pos.radius + 6}
                  fill="none"
                  stroke="#3b82f6"
                  strokeWidth="2"
                  className="animate-pulse"
                />
              )}
              
              {/* Main node */}
              <circle
                cx="0"
                cy="0"
                r={pos.radius}
                fill={style.fill}
                stroke={style.stroke}
                strokeWidth={style.strokeWidth}
                className="transition-all duration-150"
              />
              
              {/* Quality score label for high-quality domains */}
              {domain.metrics.qualityScore >= 70 && (
                <text 
                  x={pos.radius + 4} 
                  y="4" 
                  className="text-[9px] fill-zinc-400 font-mono"
                >
                  {domain.metrics.qualityScore}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Tooltip */}
      <AnimatePresence>
        {hoveredDomain && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.1 }}
            className="absolute z-50 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded-lg shadow-lg p-4 pointer-events-none min-w-[240px]"
            style={{
              left: Math.min(tooltipPos.x + 20, 640),
              top: Math.min(tooltipPos.y + 20, 440),
            }}
          >
            <div className="space-y-3">
              <div>
                <p className="text-sm font-semibold text-zinc-900 dark:text-white truncate max-w-[200px]">
                  {hoveredDomain.domain.domainName}
                </p>
                <p className="text-xs text-zinc-500">.{hoveredDomain.domain.tld}</p>
              </div>
              
              <div className="flex items-center gap-2">
                <span className={`text-lg font-bold ${
                  hoveredDomain.metrics.qualityScore >= 75 ? 'text-emerald-600' :
                  hoveredDomain.metrics.qualityScore >= 60 ? 'text-blue-600' :
                  hoveredDomain.metrics.qualityScore >= 45 ? 'text-amber-600' : 'text-red-600'
                }`}>
                  {hoveredDomain.metrics.qualityScore}
                </span>
                <span className="text-xs text-zinc-400">Quality Score</span>
              </div>
              
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <div className="flex justify-between">
                  <span className="text-zinc-500">DA:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.domainAuthority}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">PA:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.pageAuthority}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">BL:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.backlinksCount.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">TF:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.trustFlow}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Age:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">
                    {hoveredDomain.domain.birthYear 
                      ? `${new Date().getFullYear() - hoveredDomain.domain.birthYear}y` 
                      : "—"}
                  </span>
                </div>
              </div>
              
              <p className="text-[10px] text-zinc-400 pt-1 border-t border-zinc-100 dark:border-zinc-800">
                Click to view details
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Legend */}
      <div className="absolute bottom-4 right-4 bg-white/90 dark:bg-zinc-900/90 backdrop-blur-sm border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 text-xs">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-2">Quality Score</p>
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-zinc-900 dark:bg-white"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Excellent (75+)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-zinc-500"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Good (60-74)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full border-2 border-zinc-400"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Fair (45-59)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full border border-zinc-300"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Poor (&lt;45)</span>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="absolute top-4 left-4 bg-white/90 dark:bg-zinc-900/90 backdrop-blur-sm border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 text-xs">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-1">Network Stats</p>
        <p className="text-zinc-500">{domains.length} domains</p>
        <p className="text-zinc-500">
          {domains.filter(d => d.metrics.qualityScore >= 75).length} excellent
        </p>
      </div>
    </div>
  );
}

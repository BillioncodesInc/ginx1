import React, { useState, useMemo, useCallback } from "react";
import { useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { DomainResult, QUALITY_THRESHOLDS, getQualityLevel, formatDomainAge } from "@/types/domain";

interface MangoTreeProps {
  domains: DomainResult[];
}

export function MangoTree({ domains }: MangoTreeProps) {
  const [, setLocation] = useLocation();
  const [hoveredDomain, setHoveredDomain] = useState<DomainResult | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Sort domains by quality score and distribute on branches
  const sortedDomains = useMemo(() => 
    [...domains].sort((a, b) => b.metrics.qualityScore - a.metrics.qualityScore),
    [domains]
  );

  // Calculate mango positions on the tree branches
  const mangoPositions = useMemo(() => {
    const positions: { x: number; y: number; size: number; branch: number }[] = [];
    
    // Define branch endpoints (where mangoes can hang)
    const branches = [
      // Left side branches
      { startX: 450, startY: 280, endX: 180, endY: 180, count: 0, maxCount: 8 },
      { startX: 450, startY: 320, endX: 150, endY: 280, count: 0, maxCount: 10 },
      { startX: 450, startY: 360, endX: 120, endY: 380, count: 0, maxCount: 8 },
      // Right side branches
      { startX: 450, startY: 280, endX: 720, endY: 180, count: 0, maxCount: 8 },
      { startX: 450, startY: 320, endX: 750, endY: 280, count: 0, maxCount: 10 },
      { startX: 450, startY: 360, endX: 780, endY: 380, count: 0, maxCount: 8 },
      // Top branches
      { startX: 450, startY: 240, endX: 300, endY: 120, count: 0, maxCount: 6 },
      { startX: 450, startY: 240, endX: 600, endY: 120, count: 0, maxCount: 6 },
    ];

    sortedDomains.forEach((domain, index) => {
      // Find a branch with space
      let branchIndex = index % branches.length;
      let attempts = 0;
      while (branches[branchIndex].count >= branches[branchIndex].maxCount && attempts < branches.length) {
        branchIndex = (branchIndex + 1) % branches.length;
        attempts++;
      }
      
      const branch = branches[branchIndex];
      const t = 0.3 + (branch.count / branch.maxCount) * 0.6; // Position along branch
      
      // Calculate position along the branch with some randomness
      const baseX = branch.startX + (branch.endX - branch.startX) * t;
      const baseY = branch.startY + (branch.endY - branch.startY) * t;
      
      // Add slight randomness for natural look
      const jitterX = (Math.random() - 0.5) * 30;
      const jitterY = (Math.random() - 0.5) * 20 + 15; // Hang below branch
      
      // Size based on quality score (better = bigger mango)
      const size = 12 + (domain.metrics.qualityScore / 100) * 18;
      
      positions.push({
        x: baseX + jitterX,
        y: baseY + jitterY,
        size,
        branch: branchIndex
      });
      
      branch.count++;
    });
    
    return positions;
  }, [sortedDomains]);

  const handleMangoClick = useCallback((domain: DomainResult) => {
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

  // Get mango fill based on quality
  const getMangoStyle = useCallback((score: number) => {
    if (score >= 75) return { fill: "#1a1a1a", stroke: "#000", strokeWidth: 2 }; // Ripe - solid dark
    if (score >= 60) return { fill: "#3a3a3a", stroke: "#1a1a1a", strokeWidth: 1.5 }; // Good - medium
    if (score >= 45) return { fill: "none", stroke: "#4a4a4a", strokeWidth: 1.5 }; // Fair - outline
    return { fill: "none", stroke: "#8a8a8a", strokeWidth: 1 }; // Unripe - light outline
  }, []);

  return (
    <div className="relative w-full bg-white dark:bg-zinc-950 overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800">
      {/* Subtle paper texture background */}
      <div 
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E")`,
        }}
      />

      <svg 
        width="100%" 
        height="600" 
        viewBox="0 0 900 600" 
        preserveAspectRatio="xMidYMid meet"
        className="relative"
      >
        {/* Ground line */}
        <line x1="0" y1="580" x2="900" y2="580" stroke="#e5e5e5" strokeWidth="2" className="dark:stroke-zinc-800" />
        <ellipse cx="450" cy="580" rx="120" ry="15" fill="#f5f5f5" className="dark:fill-zinc-900" />

        {/* Tree trunk */}
        <path
          d="M 430 580 
             Q 420 500, 435 420 
             Q 445 350, 450 280
             Q 455 350, 465 420
             Q 480 500, 470 580
             Z"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="3"
          className="dark:stroke-zinc-300"
        />
        
        {/* Trunk texture lines */}
        <path d="M 440 550 Q 445 500, 448 450" stroke="#4a4a4a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />
        <path d="M 455 530 Q 452 480, 450 430" stroke="#4a4a4a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />
        <path d="M 460 560 Q 458 510, 455 460" stroke="#4a4a4a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />

        {/* Main branches */}
        {/* Left branches */}
        <path
          d="M 450 280 Q 350 250, 180 180"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="2.5"
          strokeLinecap="round"
          className="dark:stroke-zinc-300"
        />
        <path
          d="M 450 320 Q 320 300, 150 280"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="2"
          strokeLinecap="round"
          className="dark:stroke-zinc-300"
        />
        <path
          d="M 450 360 Q 300 370, 120 380"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="2"
          strokeLinecap="round"
          className="dark:stroke-zinc-300"
        />

        {/* Right branches */}
        <path
          d="M 450 280 Q 550 250, 720 180"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="2.5"
          strokeLinecap="round"
          className="dark:stroke-zinc-300"
        />
        <path
          d="M 450 320 Q 580 300, 750 280"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="2"
          strokeLinecap="round"
          className="dark:stroke-zinc-300"
        />
        <path
          d="M 450 360 Q 600 370, 780 380"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="2"
          strokeLinecap="round"
          className="dark:stroke-zinc-300"
        />

        {/* Top branches */}
        <path
          d="M 450 240 Q 380 180, 300 120"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="2"
          strokeLinecap="round"
          className="dark:stroke-zinc-300"
        />
        <path
          d="M 450 240 Q 520 180, 600 120"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth="2"
          strokeLinecap="round"
          className="dark:stroke-zinc-300"
        />

        {/* Small twigs */}
        <path d="M 250 200 Q 230 180, 200 160" stroke="#3a3a3a" strokeWidth="1" fill="none" className="dark:stroke-zinc-400" />
        <path d="M 650 200 Q 670 180, 700 160" stroke="#3a3a3a" strokeWidth="1" fill="none" className="dark:stroke-zinc-400" />
        <path d="M 200 300 Q 170 290, 140 270" stroke="#3a3a3a" strokeWidth="1" fill="none" className="dark:stroke-zinc-400" />
        <path d="M 700 300 Q 730 290, 760 270" stroke="#3a3a3a" strokeWidth="1" fill="none" className="dark:stroke-zinc-400" />

        {/* Leaf clusters (stylized) */}
        {[
          { x: 180, y: 170 }, { x: 150, y: 270 }, { x: 120, y: 370 },
          { x: 720, y: 170 }, { x: 750, y: 270 }, { x: 780, y: 370 },
          { x: 300, y: 110 }, { x: 600, y: 110 },
          { x: 350, y: 200 }, { x: 550, y: 200 },
        ].map((pos, i) => (
          <g key={`leaves-${i}`} transform={`translate(${pos.x}, ${pos.y})`}>
            <ellipse cx="0" cy="0" rx="25" ry="12" fill="none" stroke="#4a4a4a" strokeWidth="1" transform="rotate(-30)" className="dark:stroke-zinc-500" />
            <ellipse cx="10" cy="-5" rx="20" ry="10" fill="none" stroke="#5a5a5a" strokeWidth="0.8" transform="rotate(20)" className="dark:stroke-zinc-600" />
            <ellipse cx="-10" cy="5" rx="18" ry="9" fill="none" stroke="#5a5a5a" strokeWidth="0.8" transform="rotate(-50)" className="dark:stroke-zinc-600" />
          </g>
        ))}

        {/* Mangoes (domains) */}
        {sortedDomains.map((domain, index) => {
          const pos = mangoPositions[index];
          if (!pos) return null;
          
          const style = getMangoStyle(domain.metrics.qualityScore);
          const isHovered = hoveredDomain?.domain.id === domain.domain.id;
          
          return (
            <g
              key={domain.domain.id}
              transform={`translate(${pos.x}, ${pos.y})`}
              style={{ cursor: "pointer" }}
              onClick={() => handleMangoClick(domain)}
              onMouseEnter={(e) => handleMouseMove(e, domain)}
              onMouseLeave={() => setHoveredDomain(null)}
              onMouseMove={(e) => handleMouseMove(e, domain)}
            >
              {/* Stem */}
              <line 
                x1="0" 
                y1={-pos.size * 0.8} 
                x2="0" 
                y2={-pos.size * 1.2} 
                stroke="#4a4a4a" 
                strokeWidth="1.5"
                className="dark:stroke-zinc-500"
              />
              
              {/* Hover glow */}
              {isHovered && (
                <ellipse
                  cx="0"
                  cy="0"
                  rx={pos.size + 6}
                  ry={pos.size * 1.2 + 6}
                  fill="none"
                  stroke="#3b82f6"
                  strokeWidth="2"
                  className="animate-pulse"
                />
              )}
              
              {/* Mango shape (oval/teardrop) */}
              <ellipse
                cx="0"
                cy="0"
                rx={pos.size * 0.8}
                ry={pos.size}
                fill={style.fill}
                stroke={style.stroke}
                strokeWidth={style.strokeWidth}
                className="transition-all duration-150 dark:stroke-zinc-400"
              />
              
              {/* Mango highlight */}
              {domain.metrics.qualityScore >= 60 && (
                <ellipse
                  cx={-pos.size * 0.25}
                  cy={-pos.size * 0.3}
                  rx={pos.size * 0.15}
                  ry={pos.size * 0.2}
                  fill="none"
                  stroke={domain.metrics.qualityScore >= 75 ? "#5a5a5a" : "#7a7a7a"}
                  strokeWidth="0.5"
                  className="dark:stroke-zinc-500"
                />
              )}
              
              {/* Quality score label for excellent mangoes */}
              {domain.metrics.qualityScore >= 75 && (
                <text 
                  x={pos.size + 4} 
                  y="4" 
                  className="text-[9px] fill-zinc-500 dark:fill-zinc-400 font-mono"
                >
                  {domain.metrics.qualityScore}
                </text>
              )}
            </g>
          );
        })}

        {/* Title */}
        <text x="450" y="40" textAnchor="middle" className="text-sm fill-zinc-600 dark:fill-zinc-400 font-medium">
          Domain Harvest Tree
        </text>
        <text x="450" y="58" textAnchor="middle" className="text-[10px] fill-zinc-400 dark:fill-zinc-500">
          {domains.length} domains • Larger mangoes = Higher quality
        </text>
      </svg>

      {/* Tooltip */}
      <AnimatePresence>
        {hoveredDomain && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.1 }}
            className="absolute z-50 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded-lg shadow-xl p-4 pointer-events-none min-w-[260px]"
            style={{
              left: Math.min(tooltipPos.x + 20, 620),
              top: Math.min(tooltipPos.y + 20, 420),
            }}
          >
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-zinc-900 dark:text-white truncate max-w-[180px]">
                    {hoveredDomain.domain.domainName}
                  </p>
                  <p className="text-xs text-zinc-500">.{hoveredDomain.domain.tld}</p>
                </div>
                <div className="text-right">
                  <span className={`text-xl font-bold ${
                    hoveredDomain.metrics.qualityScore >= 75 ? 'text-zinc-900 dark:text-white' :
                    hoveredDomain.metrics.qualityScore >= 60 ? 'text-zinc-700 dark:text-zinc-300' :
                    hoveredDomain.metrics.qualityScore >= 45 ? 'text-zinc-500' : 'text-zinc-400'
                  }`}>
                    {hoveredDomain.metrics.qualityScore}
                  </span>
                  <p className="text-[10px] text-zinc-400">Quality</p>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs border-t border-zinc-100 dark:border-zinc-800 pt-3">
                <div className="flex justify-between">
                  <span className="text-zinc-500">DA:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.domainAuthority}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">PA:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.pageAuthority}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Backlinks:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.backlinksCount.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Trust Flow:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.trustFlow}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Citation:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{hoveredDomain.metrics.citationFlow}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Age:</span>
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">
                    {formatDomainAge(hoveredDomain.domain.birthYear)}
                  </span>
                </div>
              </div>
              
              <p className="text-[10px] text-zinc-400 pt-1 border-t border-zinc-100 dark:border-zinc-800">
                Click to view full details →
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Legend */}
      <div className="absolute bottom-4 right-4 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-sm border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 text-xs">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-2">Mango Ripeness</p>
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <div className="w-4 h-5 rounded-full bg-zinc-900 dark:bg-zinc-200"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Ripe (75+) - Best</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-5 rounded-full bg-zinc-500"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Good (60-74)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-5 rounded-full border-2 border-zinc-400"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Fair (45-59)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-5 rounded-full border border-zinc-300"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Unripe (&lt;45)</span>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="absolute top-4 left-4 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-sm border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 text-xs">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-1">Harvest Stats</p>
        <p className="text-zinc-500">{domains.length} total mangoes</p>
        <p className="text-zinc-500">
          {domains.filter(d => d.metrics.qualityScore >= 75).length} ripe (ready to pick)
        </p>
        <p className="text-zinc-500">
          {domains.filter(d => d.metrics.qualityScore >= 60 && d.metrics.qualityScore < 75).length} almost ripe
        </p>
      </div>
    </div>
  );
}

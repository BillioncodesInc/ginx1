import React, { useState, useRef, useCallback, useMemo, useEffect } from "react";
import { useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { DomainResult, QUALITY_THRESHOLDS, getQualityLevel } from "@/types/domain";

interface MangoTreeSketchProps {
  domains: DomainResult[];
}

export function MangoTreeSketch({ domains }: MangoTreeSketchProps) {
  const [, setLocation] = useLocation();
  const [hoveredDomain, setHoveredDomain] = useState<DomainResult | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [rotation, setRotation] = useState(0);
  const [isDragging, setIsDragging] = useState(false);
  const [startX, setStartX] = useState(0);
  const [scale, setScale] = useState(1);
  const containerRef = useRef<HTMLDivElement>(null);

  // Sort domains by quality
  const sortedDomains = useMemo(() => 
    [...domains].sort((a, b) => b.metrics.qualityScore - a.metrics.qualityScore),
    [domains]
  );

  // Calculate mango positions distributed around the tree
  const mangoPositions = useMemo(() => {
    const positions: { x: number; y: number; size: number; depth: number; stemLength: number }[] = [];
    
    sortedDomains.forEach((domain, index) => {
      // Distribute mangoes in a natural pattern around the tree canopy
      const angle = (index / sortedDomains.length) * Math.PI * 2;
      const layer = Math.floor(index / 8); // 8 mangoes per layer
      const layerOffset = (index % 8) / 8 * Math.PI * 2;
      
      // Position within the tree canopy area
      const radiusX = 120 + layer * 40 + Math.random() * 30;
      const radiusY = 80 + layer * 25 + Math.random() * 20;
      
      const baseX = 450 + Math.cos(angle + layerOffset) * radiusX;
      const baseY = 220 + Math.sin(angle + layerOffset) * radiusY * 0.6;
      
      // Depth for 3D effect (0 = front, 1 = back)
      const depth = (Math.sin(angle + layerOffset) + 1) / 2;
      
      // Size based on quality score
      const size = 15 + (domain.metrics.qualityScore / 100) * 20;
      
      // Stem length
      const stemLength = 15 + Math.random() * 10;
      
      positions.push({
        x: baseX,
        y: baseY,
        size,
        depth,
        stemLength
      });
    });
    
    return positions;
  }, [sortedDomains]);

  // Handle mouse drag for rotation
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setStartX(e.clientX);
  };

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (isDragging) {
      const deltaX = e.clientX - startX;
      setRotation(prev => prev + deltaX * 0.5);
      setStartX(e.clientX);
    }
  }, [isDragging, startX]);

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  // Handle scroll for zoom
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setScale(prev => Math.max(0.5, Math.min(2, prev + delta)));
  }, []);

  const handleMangoClick = useCallback((domain: DomainResult) => {
    // Use domain name route since job results may not have real database IDs
    setLocation(`/d/${encodeURIComponent(domain.domain.domainName)}`);
  }, [setLocation]);

  const handleMangoHover = useCallback((e: React.MouseEvent, domain: DomainResult) => {
    setHoveredDomain(domain);
    const rect = containerRef.current?.getBoundingClientRect();
    if (rect) {
      setTooltipPos({ 
        x: e.clientX - rect.left, 
        y: e.clientY - rect.top 
      });
    }
  }, []);

  // Get mango style based on quality (sketch style - black & white)
  const getMangoStyle = useCallback((score: number) => {
    if (score >= 75) return { fill: "#1a1a1a", stroke: "#000", strokeWidth: 2 }; // Ripe - solid
    if (score >= 60) return { fill: "#4a4a4a", stroke: "#2a2a2a", strokeWidth: 1.5 }; // Good
    if (score >= 45) return { fill: "none", stroke: "#3a3a3a", strokeWidth: 1.5 }; // Fair - outline
    return { fill: "none", stroke: "#6a6a6a", strokeWidth: 1 }; // Unripe - light outline
  }, []);

  // Calculate 3D transform based on rotation
  const getTransform = useCallback((depth: number, baseX: number) => {
    const rotRad = (rotation * Math.PI) / 180;
    const offsetX = Math.sin(rotRad) * (depth - 0.5) * 100;
    const scaleZ = 0.8 + Math.cos(rotRad) * (depth - 0.5) * 0.4;
    return { offsetX, scaleZ };
  }, [rotation]);

  const ripeCount = domains.filter(d => d.metrics.qualityScore >= 75).length;
  const goodCount = domains.filter(d => d.metrics.qualityScore >= 60 && d.metrics.qualityScore < 75).length;

  return (
    <div 
      ref={containerRef}
      className="relative w-full bg-white dark:bg-zinc-950 overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800 select-none"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      onWheel={handleWheel}
      style={{ cursor: isDragging ? 'grabbing' : 'grab' }}
    >
      {/* Paper texture background */}
      <div 
        className="absolute inset-0 opacity-[0.02] pointer-events-none"
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
        style={{ transform: `scale(${scale})`, transformOrigin: 'center center' }}
      >
        <defs>
          {/* Sketch-style filter for hand-drawn look */}
          <filter id="sketch" x="-5%" y="-5%" width="110%" height="110%">
            <feTurbulence type="fractalNoise" baseFrequency="0.04" numOctaves="5" result="noise"/>
            <feDisplacementMap in="SourceGraphic" in2="noise" scale="2" xChannelSelector="R" yChannelSelector="G"/>
          </filter>
        </defs>

        {/* Ground with grass */}
        <g filter="url(#sketch)">
          <path 
            d="M 300 580 Q 350 575, 400 578 Q 450 582, 500 578 Q 550 575, 600 580" 
            stroke="#3a3a3a" 
            strokeWidth="1.5" 
            fill="none"
            className="dark:stroke-zinc-500"
          />
          {/* Grass tufts */}
          {[320, 360, 400, 440, 480, 520, 560].map((x, i) => (
            <g key={`grass-${i}`}>
              <path d={`M ${x} 580 Q ${x-3} 570, ${x-5} 565`} stroke="#4a4a4a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />
              <path d={`M ${x} 580 Q ${x} 568, ${x} 562`} stroke="#4a4a4a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />
              <path d={`M ${x} 580 Q ${x+3} 570, ${x+5} 565`} stroke="#4a4a4a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />
            </g>
          ))}
        </g>

        {/* Tree trunk - sketch style */}
        <g filter="url(#sketch)">
          <path
            d="M 430 580 
               Q 425 550, 428 500 
               Q 432 450, 435 400
               Q 438 350, 445 320
               Q 450 300, 450 280
               Q 450 300, 455 320
               Q 462 350, 465 400
               Q 468 450, 472 500
               Q 475 550, 470 580
               Z"
            fill="none"
            stroke="#2a2a2a"
            strokeWidth="2"
            className="dark:stroke-zinc-400"
          />
          {/* Trunk texture lines */}
          <path d="M 438 560 Q 442 520, 445 480 Q 448 440, 450 400" stroke="#4a4a4a" strokeWidth="0.8" fill="none" className="dark:stroke-zinc-500" />
          <path d="M 455 550 Q 453 510, 452 470 Q 451 430, 450 390" stroke="#4a4a4a" strokeWidth="0.8" fill="none" className="dark:stroke-zinc-500" />
          <path d="M 462 540 Q 458 500, 455 460" stroke="#4a4a4a" strokeWidth="0.8" fill="none" className="dark:stroke-zinc-500" />
        </g>

        {/* Main branches */}
        <g filter="url(#sketch)">
          {/* Left main branch */}
          <path d="M 445 320 Q 380 300, 280 260" stroke="#2a2a2a" strokeWidth="2" fill="none" className="dark:stroke-zinc-400" />
          <path d="M 320 280 Q 260 260, 200 240" stroke="#3a3a3a" strokeWidth="1.5" fill="none" className="dark:stroke-zinc-500" />
          <path d="M 350 270 Q 300 230, 250 200" stroke="#3a3a3a" strokeWidth="1.5" fill="none" className="dark:stroke-zinc-500" />
          
          {/* Right main branch */}
          <path d="M 455 320 Q 520 300, 620 260" stroke="#2a2a2a" strokeWidth="2" fill="none" className="dark:stroke-zinc-400" />
          <path d="M 580 280 Q 640 260, 700 240" stroke="#3a3a3a" strokeWidth="1.5" fill="none" className="dark:stroke-zinc-500" />
          <path d="M 550 270 Q 600 230, 650 200" stroke="#3a3a3a" strokeWidth="1.5" fill="none" className="dark:stroke-zinc-500" />
          
          {/* Top branches */}
          <path d="M 450 280 Q 420 220, 350 160" stroke="#3a3a3a" strokeWidth="1.5" fill="none" className="dark:stroke-zinc-500" />
          <path d="M 450 280 Q 480 220, 550 160" stroke="#3a3a3a" strokeWidth="1.5" fill="none" className="dark:stroke-zinc-500" />
          <path d="M 450 280 Q 450 200, 450 140" stroke="#3a3a3a" strokeWidth="1.5" fill="none" className="dark:stroke-zinc-500" />
          
          {/* Small twigs */}
          <path d="M 280 260 Q 250 250, 220 260" stroke="#4a4a4a" strokeWidth="1" fill="none" className="dark:stroke-zinc-600" />
          <path d="M 620 260 Q 650 250, 680 260" stroke="#4a4a4a" strokeWidth="1" fill="none" className="dark:stroke-zinc-600" />
        </g>

        {/* Leaves - sketch style mango leaves */}
        <g filter="url(#sketch)">
          {/* Generate leaf clusters */}
          {[
            // Top area
            { x: 350, y: 150 }, { x: 400, y: 130 }, { x: 450, y: 120 }, { x: 500, y: 130 }, { x: 550, y: 150 },
            { x: 380, y: 170 }, { x: 450, y: 150 }, { x: 520, y: 170 },
            // Left side
            { x: 220, y: 230 }, { x: 260, y: 200 }, { x: 300, y: 180 }, { x: 250, y: 260 }, { x: 200, y: 250 },
            { x: 280, y: 240 }, { x: 320, y: 220 }, { x: 340, y: 200 },
            // Right side
            { x: 680, y: 230 }, { x: 640, y: 200 }, { x: 600, y: 180 }, { x: 650, y: 260 }, { x: 700, y: 250 },
            { x: 620, y: 240 }, { x: 580, y: 220 }, { x: 560, y: 200 },
            // Middle fill
            { x: 380, y: 220 }, { x: 420, y: 200 }, { x: 480, y: 200 }, { x: 520, y: 220 },
            { x: 400, y: 250 }, { x: 450, y: 230 }, { x: 500, y: 250 },
            { x: 360, y: 280 }, { x: 540, y: 280 },
          ].map((pos, i) => (
            <g key={`leaf-cluster-${i}`} transform={`translate(${pos.x}, ${pos.y})`}>
              {/* Each cluster has 3-5 leaves */}
              <path d="M 0 0 Q -15 -8, -25 0 Q -15 8, 0 0" stroke="#3a3a3a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />
              <path d="M 0 0 Q 15 -10, 28 -5 Q 15 5, 0 0" stroke="#3a3a3a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />
              <path d="M 0 0 Q 5 -18, 0 -30 Q -5 -18, 0 0" stroke="#3a3a3a" strokeWidth="1" fill="none" className="dark:stroke-zinc-500" />
              <path d="M 0 0 Q -10 -15, -20 -20 Q -5 -10, 0 0" stroke="#4a4a4a" strokeWidth="0.8" fill="none" className="dark:stroke-zinc-600" />
              <path d="M 0 0 Q 10 -15, 20 -20 Q 5 -10, 0 0" stroke="#4a4a4a" strokeWidth="0.8" fill="none" className="dark:stroke-zinc-600" />
            </g>
          ))}
        </g>

        {/* Mangoes (domains) - sorted by depth for proper layering */}
        {sortedDomains
          .map((domain, index) => ({ domain, index, pos: mangoPositions[index] }))
          .sort((a, b) => (b.pos?.depth || 0) - (a.pos?.depth || 0))
          .map(({ domain, index, pos }) => {
            if (!pos) return null;
            
            const style = getMangoStyle(domain.metrics.qualityScore);
            const { offsetX, scaleZ } = getTransform(pos.depth, pos.x);
            const isHovered = hoveredDomain?.domain.id === domain.domain.id;
            const adjustedX = pos.x + offsetX;
            const adjustedSize = pos.size * scaleZ;
            const opacity = 0.5 + scaleZ * 0.5;
            
            return (
              <g
                key={domain.domain.id}
                transform={`translate(${adjustedX}, ${pos.y})`}
                style={{ cursor: "pointer", opacity }}
                onClick={() => handleMangoClick(domain)}
                onMouseEnter={(e) => handleMangoHover(e, domain)}
                onMouseLeave={() => setHoveredDomain(null)}
                filter="url(#sketch)"
              >
                {/* Stem */}
                <path 
                  d={`M 0 ${-adjustedSize * 0.8} Q 2 ${-adjustedSize * 0.8 - pos.stemLength/2}, 0 ${-adjustedSize * 0.8 - pos.stemLength}`}
                  stroke="#3a3a3a" 
                  strokeWidth="1.5"
                  fill="none"
                  className="dark:stroke-zinc-500"
                />
                
                {/* Hover highlight */}
                {isHovered && (
                  <ellipse
                    cx="0"
                    cy="0"
                    rx={adjustedSize * 0.7 + 5}
                    ry={adjustedSize + 5}
                    fill="none"
                    stroke="#3b82f6"
                    strokeWidth="2"
                    className="animate-pulse"
                  />
                )}
                
                {/* Mango shape - teardrop/oval */}
                <ellipse
                  cx="0"
                  cy="0"
                  rx={adjustedSize * 0.65}
                  ry={adjustedSize}
                  fill={style.fill}
                  stroke={style.stroke}
                  strokeWidth={style.strokeWidth}
                  className="dark:stroke-zinc-400"
                />
                
                {/* Mango tip */}
                <path
                  d={`M 0 ${adjustedSize} Q ${adjustedSize * 0.2} ${adjustedSize * 1.2}, 0 ${adjustedSize * 1.3}`}
                  stroke={style.stroke}
                  strokeWidth={style.strokeWidth * 0.8}
                  fill="none"
                  className="dark:stroke-zinc-400"
                />
                
                {/* Quality score for high quality */}
                {domain.metrics.qualityScore >= 70 && (
                  <text 
                    x={adjustedSize * 0.8 + 5} 
                    y="4" 
                    className="text-[9px] fill-zinc-500 dark:fill-zinc-400 font-mono"
                    style={{ pointerEvents: 'none' }}
                  >
                    {domain.metrics.qualityScore}
                  </text>
                )}
              </g>
            );
          })}

        {/* Title */}
        <text x="450" y="35" textAnchor="middle" className="text-sm fill-zinc-600 dark:fill-zinc-400 font-medium" style={{ fontFamily: 'serif' }}>
          Domain Harvest Tree
        </text>
        <text x="450" y="55" textAnchor="middle" className="text-[10px] fill-zinc-400 dark:fill-zinc-500">
          {domains.length} domains • Drag to rotate • Scroll to zoom
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
            className="absolute z-50 bg-white dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded-lg shadow-xl p-4 pointer-events-none min-w-[260px]"
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
              
              <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs border-t border-zinc-200 dark:border-zinc-800 pt-3">
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
              </div>
              
              <p className="text-[10px] text-zinc-400 pt-1 border-t border-zinc-200 dark:border-zinc-800">
                Click to view details →
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Stats */}
      <div className="absolute top-4 left-4 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-sm border border-zinc-300 dark:border-zinc-700 rounded-lg p-3 text-xs">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-1">🥭 Harvest Stats</p>
        <p className="text-zinc-500">{domains.length} total mangoes</p>
        <p className="text-zinc-500">{ripeCount} ripe (ready)</p>
        <p className="text-zinc-500">{goodCount} almost ripe</p>
      </div>

      {/* Controls */}
      <div className="absolute bottom-4 left-4 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-sm border border-zinc-300 dark:border-zinc-700 rounded-lg p-3 text-xs">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-1">🖱️ Controls</p>
        <p className="text-zinc-500">Drag to rotate</p>
        <p className="text-zinc-500">Scroll to zoom</p>
        <p className="text-zinc-500">Click mango for details</p>
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 right-4 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-sm border border-zinc-300 dark:border-zinc-700 rounded-lg p-3 text-xs">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-2">Mango Ripeness</p>
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <div className="w-4 h-5 rounded-sm bg-zinc-900 dark:bg-zinc-200"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Ripe (75+)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-5 rounded-sm bg-zinc-500"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Good (60-74)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-5 rounded-sm border-2 border-zinc-400"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Fair (45-59)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-5 rounded-sm border border-zinc-300"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Unripe (&lt;45)</span>
          </div>
        </div>
      </div>
    </div>
  );
}

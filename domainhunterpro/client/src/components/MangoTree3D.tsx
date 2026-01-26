import React, { useRef, useState, useMemo, Suspense } from "react";
import { Canvas, useFrame, useThree, ThreeEvent } from "@react-three/fiber";
import { OrbitControls, Html, Environment } from "@react-three/drei";
import * as THREE from "three";
import { useLocation } from "wouter";
import { DomainResult, QUALITY_THRESHOLDS, getQualityLevel } from "@/types/domain";

interface MangoTree3DProps {
  domains: DomainResult[];
}

// Leaf cluster component
function LeafCluster({ position, scale = 1 }: { position: [number, number, number]; scale?: number }) {
  const meshRef = useRef<THREE.Mesh>(null);
  
  // Slight animation
  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.5 + position[0]) * 0.05;
    }
  });

  return (
    <mesh ref={meshRef} position={position}>
      <sphereGeometry args={[0.8 * scale, 16, 16]} />
      <meshStandardMaterial 
        color="#2d5016" 
        roughness={0.8} 
        metalness={0.1}
      />
    </mesh>
  );
}

// Tree trunk and branches
function TreeStructure() {
  return (
    <group>
      {/* Main trunk */}
      <mesh position={[0, -1, 0]}>
        <cylinderGeometry args={[0.15, 0.25, 3, 12]} />
        <meshStandardMaterial color="#4a3728" roughness={0.9} />
      </mesh>
      
      {/* Branch 1 - left */}
      <mesh position={[-0.8, 0.8, 0]} rotation={[0, 0, Math.PI / 4]}>
        <cylinderGeometry args={[0.06, 0.1, 1.8, 8]} />
        <meshStandardMaterial color="#5a4738" roughness={0.9} />
      </mesh>
      
      {/* Branch 2 - right */}
      <mesh position={[0.8, 0.8, 0]} rotation={[0, 0, -Math.PI / 4]}>
        <cylinderGeometry args={[0.06, 0.1, 1.8, 8]} />
        <meshStandardMaterial color="#5a4738" roughness={0.9} />
      </mesh>
      
      {/* Branch 3 - front */}
      <mesh position={[0, 0.9, 0.7]} rotation={[Math.PI / 4, 0, 0]}>
        <cylinderGeometry args={[0.05, 0.08, 1.5, 8]} />
        <meshStandardMaterial color="#5a4738" roughness={0.9} />
      </mesh>
      
      {/* Branch 4 - back */}
      <mesh position={[0, 0.9, -0.7]} rotation={[-Math.PI / 4, 0, 0]}>
        <cylinderGeometry args={[0.05, 0.08, 1.5, 8]} />
        <meshStandardMaterial color="#5a4738" roughness={0.9} />
      </mesh>
      
      {/* Branch 5 - top */}
      <mesh position={[0, 1.5, 0]}>
        <cylinderGeometry args={[0.04, 0.08, 1.2, 8]} />
        <meshStandardMaterial color="#5a4738" roughness={0.9} />
      </mesh>
    </group>
  );
}

// Foliage (leaves)
function Foliage() {
  const leafPositions: [number, number, number][] = [
    // Top cluster
    [0, 2.2, 0],
    [0.3, 2.0, 0.3],
    [-0.3, 2.0, -0.3],
    [0.2, 2.3, -0.2],
    [-0.2, 2.1, 0.2],
    
    // Left branch clusters
    [-1.4, 1.4, 0],
    [-1.6, 1.2, 0.3],
    [-1.3, 1.5, -0.3],
    [-1.5, 1.6, 0.2],
    [-1.2, 1.3, 0.4],
    
    // Right branch clusters
    [1.4, 1.4, 0],
    [1.6, 1.2, 0.3],
    [1.3, 1.5, -0.3],
    [1.5, 1.6, 0.2],
    [1.2, 1.3, -0.4],
    
    // Front branch clusters
    [0, 1.5, 1.2],
    [0.3, 1.4, 1.4],
    [-0.3, 1.6, 1.3],
    [0.2, 1.3, 1.5],
    
    // Back branch clusters
    [0, 1.5, -1.2],
    [0.3, 1.4, -1.4],
    [-0.3, 1.6, -1.3],
    [-0.2, 1.3, -1.5],
    
    // Middle fill
    [0.5, 1.8, 0.5],
    [-0.5, 1.8, -0.5],
    [0.5, 1.7, -0.5],
    [-0.5, 1.7, 0.5],
    [0, 1.6, 0.6],
    [0, 1.6, -0.6],
    [0.6, 1.6, 0],
    [-0.6, 1.6, 0],
  ];

  return (
    <group>
      {leafPositions.map((pos, i) => (
        <LeafCluster 
          key={i} 
          position={pos} 
          scale={0.6 + Math.random() * 0.4}
        />
      ))}
    </group>
  );
}

// Single mango component
function Mango({ 
  domain, 
  position, 
  onHover, 
  onUnhover,
  onClick 
}: { 
  domain: DomainResult;
  position: [number, number, number];
  onHover: (domain: DomainResult, position: THREE.Vector3) => void;
  onUnhover: () => void;
  onClick: (domain: DomainResult) => void;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const [hovered, setHovered] = useState(false);
  
  // Size based on quality score
  const size = 0.08 + (domain.metrics.qualityScore / 100) * 0.12;
  
  // Color based on quality (grayscale)
  const getColor = (score: number) => {
    if (score >= 75) return "#1a1a1a"; // Ripe - dark
    if (score >= 60) return "#4a4a4a"; // Good - medium gray
    if (score >= 45) return "#7a7a7a"; // Fair - light gray
    return "#aaaaaa"; // Unripe - very light
  };

  // Gentle sway animation
  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.position.y = position[1] + Math.sin(state.clock.elapsedTime * 2 + position[0] * 10) * 0.02;
    }
  });

  const handlePointerOver = (e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    setHovered(true);
    document.body.style.cursor = 'pointer';
    if (meshRef.current) {
      const worldPos = new THREE.Vector3();
      meshRef.current.getWorldPosition(worldPos);
      onHover(domain, worldPos);
    }
  };

  const handlePointerOut = () => {
    setHovered(false);
    document.body.style.cursor = 'auto';
    onUnhover();
  };

  const handleClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    onClick(domain);
  };

  return (
    <group position={position}>
      {/* Stem */}
      <mesh position={[0, size + 0.03, 0]}>
        <cylinderGeometry args={[0.008, 0.008, 0.06, 6]} />
        <meshStandardMaterial color="#3a2a1a" />
      </mesh>
      
      {/* Mango fruit */}
      <mesh
        ref={meshRef}
        onPointerOver={handlePointerOver}
        onPointerOut={handlePointerOut}
        onClick={handleClick}
        scale={hovered ? 1.2 : 1}
      >
        <sphereGeometry args={[size, 16, 16]} />
        <meshStandardMaterial 
          color={getColor(domain.metrics.qualityScore)}
          roughness={0.6}
          metalness={0.1}
          emissive={hovered ? "#3b82f6" : "#000000"}
          emissiveIntensity={hovered ? 0.3 : 0}
        />
      </mesh>
      
      {/* Quality score label for high quality */}
      {domain.metrics.qualityScore >= 70 && (
        <Html position={[size + 0.1, 0, 0]} style={{ pointerEvents: 'none' }}>
          <span className="text-[10px] font-mono text-zinc-500 bg-white/80 px-1 rounded">
            {domain.metrics.qualityScore}
          </span>
        </Html>
      )}
    </group>
  );
}

// All mangoes distributed on the tree
function Mangoes({ 
  domains, 
  onHover, 
  onUnhover,
  onClick 
}: { 
  domains: DomainResult[];
  onHover: (domain: DomainResult, position: THREE.Vector3) => void;
  onUnhover: () => void;
  onClick: (domain: DomainResult) => void;
}) {
  // Calculate positions for mangoes distributed around the tree
  const mangoPositions = useMemo(() => {
    const positions: [number, number, number][] = [];
    const sortedDomains = [...domains].sort((a, b) => b.metrics.qualityScore - a.metrics.qualityScore);
    
    sortedDomains.forEach((_, index) => {
      // Distribute in a spherical pattern around the foliage
      const phi = Math.acos(-1 + (2 * index) / domains.length);
      const theta = Math.sqrt(domains.length * Math.PI) * phi;
      
      const radius = 1.0 + Math.random() * 0.5;
      const x = radius * Math.sin(phi) * Math.cos(theta);
      const y = 1.2 + radius * Math.cos(phi) * 0.5 + Math.random() * 0.3;
      const z = radius * Math.sin(phi) * Math.sin(theta);
      
      positions.push([x, y, z]);
    });
    
    return positions;
  }, [domains]);

  const sortedDomains = useMemo(() => 
    [...domains].sort((a, b) => b.metrics.qualityScore - a.metrics.qualityScore),
    [domains]
  );

  return (
    <group>
      {sortedDomains.map((domain, index) => (
        <Mango
          key={domain.domain.id}
          domain={domain}
          position={mangoPositions[index]}
          onHover={onHover}
          onUnhover={onUnhover}
          onClick={onClick}
        />
      ))}
    </group>
  );
}

// Ground
function Ground() {
  return (
    <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -2.5, 0]} receiveShadow>
      <circleGeometry args={[3, 32]} />
      <meshStandardMaterial color="#e8e4e0" roughness={1} />
    </mesh>
  );
}

// Main scene
function Scene({ 
  domains, 
  onHover, 
  onUnhover,
  onClick 
}: { 
  domains: DomainResult[];
  onHover: (domain: DomainResult, position: THREE.Vector3) => void;
  onUnhover: () => void;
  onClick: (domain: DomainResult) => void;
}) {
  return (
    <>
      <ambientLight intensity={0.6} />
      <directionalLight position={[5, 10, 5]} intensity={1} castShadow />
      <directionalLight position={[-5, 5, -5]} intensity={0.3} />
      
      <TreeStructure />
      <Foliage />
      <Mangoes 
        domains={domains} 
        onHover={onHover} 
        onUnhover={onUnhover}
        onClick={onClick}
      />
      <Ground />
      
      <OrbitControls 
        enablePan={false}
        minDistance={3}
        maxDistance={10}
        minPolarAngle={Math.PI / 6}
        maxPolarAngle={Math.PI / 2}
        autoRotate
        autoRotateSpeed={0.5}
      />
    </>
  );
}

// Tooltip component
function Tooltip({ domain, visible }: { domain: DomainResult | null; visible: boolean }) {
  if (!visible || !domain) return null;

  return (
    <div className="absolute top-4 right-4 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded-lg shadow-xl p-4 min-w-[260px] z-50">
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-sm font-semibold text-zinc-900 dark:text-white truncate max-w-[180px]">
              {domain.domain.domainName}
            </p>
            <p className="text-xs text-zinc-500">.{domain.domain.tld}</p>
          </div>
          <div className="text-right">
            <span className={`text-xl font-bold ${
              domain.metrics.qualityScore >= 75 ? 'text-zinc-900 dark:text-white' :
              domain.metrics.qualityScore >= 60 ? 'text-zinc-700 dark:text-zinc-300' :
              domain.metrics.qualityScore >= 45 ? 'text-zinc-500' : 'text-zinc-400'
            }`}>
              {domain.metrics.qualityScore}
            </span>
            <p className="text-[10px] text-zinc-400">Quality</p>
          </div>
        </div>
        
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs border-t border-zinc-100 dark:border-zinc-800 pt-3">
          <div className="flex justify-between">
            <span className="text-zinc-500">DA:</span>
            <span className="font-medium text-zinc-700 dark:text-zinc-300">{domain.metrics.domainAuthority}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">PA:</span>
            <span className="font-medium text-zinc-700 dark:text-zinc-300">{domain.metrics.pageAuthority}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">Backlinks:</span>
            <span className="font-medium text-zinc-700 dark:text-zinc-300">{domain.metrics.backlinksCount.toLocaleString()}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">Trust Flow:</span>
            <span className="font-medium text-zinc-700 dark:text-zinc-300">{domain.metrics.trustFlow}</span>
          </div>
        </div>
        
        <p className="text-[10px] text-zinc-400 pt-1 border-t border-zinc-100 dark:border-zinc-800">
          Click mango to view details
        </p>
      </div>
    </div>
  );
}

// Main component
export function MangoTree3D({ domains }: MangoTree3DProps) {
  const [, setLocation] = useLocation();
  const [hoveredDomain, setHoveredDomain] = useState<DomainResult | null>(null);
  const [tooltipVisible, setTooltipVisible] = useState(false);

  const handleHover = (domain: DomainResult, _position: THREE.Vector3) => {
    setHoveredDomain(domain);
    setTooltipVisible(true);
  };

  const handleUnhover = () => {
    setTooltipVisible(false);
  };

  const handleClick = (domain: DomainResult) => {
    setLocation(`/domain/${domain.domain.id}`);
  };

  const ripeCount = domains.filter(d => d.metrics.qualityScore >= 75).length;
  const goodCount = domains.filter(d => d.metrics.qualityScore >= 60 && d.metrics.qualityScore < 75).length;

  return (
    <div className="relative w-full h-[600px] bg-gradient-to-b from-sky-100 to-sky-50 dark:from-zinc-900 dark:to-zinc-950 rounded-lg overflow-hidden">
      {/* Stats */}
      <div className="absolute top-4 left-4 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-sm border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 text-xs z-10">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-1">🥭 Harvest Stats</p>
        <p className="text-zinc-500">{domains.length} total mangoes</p>
        <p className="text-zinc-500">{ripeCount} ripe (ready to pick)</p>
        <p className="text-zinc-500">{goodCount} almost ripe</p>
      </div>

      {/* Controls hint */}
      <div className="absolute bottom-4 left-4 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-sm border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 text-xs z-10">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-1">🖱️ Controls</p>
        <p className="text-zinc-500">Drag to rotate</p>
        <p className="text-zinc-500">Scroll to zoom</p>
        <p className="text-zinc-500">Click mango for details</p>
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 right-4 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-sm border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 text-xs z-10">
        <p className="font-medium text-zinc-700 dark:text-zinc-300 mb-2">Mango Ripeness</p>
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full bg-zinc-900"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Ripe (75+)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full bg-zinc-500"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Good (60-74)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full bg-zinc-400"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Fair (45-59)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full bg-zinc-300"></div>
            <span className="text-zinc-600 dark:text-zinc-400">Unripe (&lt;45)</span>
          </div>
        </div>
      </div>

      {/* Tooltip */}
      <Tooltip domain={hoveredDomain} visible={tooltipVisible} />

      {/* 3D Canvas */}
      <Canvas
        camera={{ position: [4, 2, 4], fov: 50 }}
        shadows
      >
        <Suspense fallback={null}>
          <Scene 
            domains={domains}
            onHover={handleHover}
            onUnhover={handleUnhover}
            onClick={handleClick}
          />
        </Suspense>
      </Canvas>
    </div>
  );
}

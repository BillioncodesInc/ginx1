import { useState } from "react";
import { useRoute, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import { 
  ArrowLeft, ExternalLink, Loader2, Calendar, Link2, 
  TrendingUp, Shield, Archive, Globe, Zap, BarChart3,
  Clock, CheckCircle2, AlertTriangle, Search, Server, Network, LinkIcon
} from "lucide-react";

interface SubdomainResult {
  subdomain: string;
  ip?: string;
  source: string;
  recordType?: string;
  discovered: Date;
}

interface SubdomainDiscoveryResult {
  success: boolean;
  jobId: string;
  domain: string;
  subdomains: SubdomainResult[];
  dnsRecords: {
    ns: string[];
    mx: { exchange: string; priority: number }[];
    txt: string[];
    cname: string[];
  };
  totalFound: number;
  techniques: string[];
  duration: number;
}

interface BacklinkResult {
  sourceUrl: string;
  sourceTitle?: string;
  targetUrl: string;
  anchorText?: string;
  domainRating?: number;
  isDofollow: boolean;
  firstSeen?: Date;
}

interface BacklinkProfile {
  success: boolean;
  jobId: string;
  domain: string;
  totalBacklinks: number;
  uniqueDomains: number;
  dofollowPercent: number;
  nofollowPercent: number;
  backlinks: BacklinkResult[];
  topReferringDomains: { domain: string; count: number; rating?: number }[];
  anchorTexts: { text: string; count: number }[];
  duration: number;
  sources?: string[];
  message?: string;
}

export default function DomainDetail() {
  const [, paramsById] = useRoute("/domain/:id");
  const [, paramsByName] = useRoute("/d/:name");
  const [, setLocation] = useLocation();

  // Support both /domain/:id (numeric) and /d/:name (domain name) routes
  const domainId = paramsById?.id ? parseInt(paramsById.id) : 0;
  const domainName = paramsByName?.name ? decodeURIComponent(paramsByName.name) : null;
  const isNumericId = Boolean(paramsById?.id && !isNaN(domainId) && domainId > 0);

  // Subdomain discovery state
  const [subdomainResults, setSubdomainResults] = useState<SubdomainDiscoveryResult | null>(null);
  const [isDiscovering, setIsDiscovering] = useState(false);

  // Backlink analysis state
  const [backlinkResults, setBacklinkResults] = useState<BacklinkProfile | null>(null);
  const [isAnalyzingBacklinks, setIsAnalyzingBacklinks] = useState(false);

  // Query by ID if numeric, otherwise by name
  const { data: domainDataById, isLoading: isLoadingById } = trpc.domains.getById.useQuery(
    { id: domainId },
    { enabled: isNumericId }
  );

  const { data: domainDataByName, isLoading: isLoadingByName } = trpc.domains.getByName.useQuery(
    { name: domainName || '' },
    { enabled: !!domainName }
  );

  // Use whichever data source is available
  const domainData = domainDataById || domainDataByName;
  const isLoading = isNumericId ? isLoadingById : isLoadingByName;

  // Subdomain discovery mutation
  const discoverSubdomainsMutation = trpc.domains.discoverSubdomains.useMutation({
    onSuccess: (data) => {
      setSubdomainResults(data as SubdomainDiscoveryResult);
      setIsDiscovering(false);
      if (data.success) {
        toast.success(`Found ${data.totalFound} subdomains in ${(data.duration / 1000).toFixed(1)}s`);
      } else {
        toast.error('Subdomain discovery failed');
      }
    },
    onError: (error) => {
      setIsDiscovering(false);
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleDiscoverSubdomains = () => {
    if (!domainData) return;
    setIsDiscovering(true);
    setSubdomainResults(null);
    discoverSubdomainsMutation.mutate({ domain: domainData.domain.domainName });
  };

  // Backlink analysis mutation
  const analyzeBacklinksMutation = trpc.domains.getBacklinks.useMutation({
    onSuccess: (data) => {
      setBacklinkResults(data as BacklinkProfile);
      setIsAnalyzingBacklinks(false);
      if (data.success) {
        toast.success(`Found ${data.totalBacklinks} backlinks from ${data.uniqueDomains} domains`);
      } else {
        toast.error('Backlink analysis failed');
      }
    },
    onError: (error) => {
      setIsAnalyzingBacklinks(false);
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleAnalyzeBacklinks = () => {
    if (!domainData) return;
    setIsAnalyzingBacklinks(true);
    setBacklinkResults(null);
    analyzeBacklinksMutation.mutate({ domain: domainData.domain.domainName });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-zinc-400" />
          <p className="text-sm text-zinc-500">Loading domain details...</p>
        </div>
      </div>
    );
  }

  if (!domainData) {
    return (
      <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 flex items-center justify-center">
        <Card className="max-w-md bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
          <CardContent className="py-12 text-center">
            <Globe className="h-12 w-12 mx-auto mb-4 text-zinc-300 dark:text-zinc-700" />
            <p className="text-lg font-medium text-zinc-900 dark:text-white mb-2">Domain not found</p>
            <p className="text-sm text-zinc-500 mb-4">The domain you're looking for doesn't exist.</p>
            <Button onClick={() => setLocation("/")}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Search
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const { domain, metrics } = domainData;
  const currentYear = new Date().getFullYear();
  const domainAge = domain.birthYear ? currentYear - domain.birthYear : null;

  const getQualityColor = (score: number) => {
    if (score >= 75) return "text-emerald-600";
    if (score >= 60) return "text-blue-600";
    if (score >= 45) return "text-amber-600";
    return "text-red-600";
  };

  const getQualityBg = (score: number) => {
    if (score >= 75) return "bg-emerald-500";
    if (score >= 60) return "bg-blue-500";
    if (score >= 45) return "bg-amber-500";
    return "bg-red-500";
  };

  const getQualityLabel = (score: number) => {
    if (score >= 75) return "Excellent";
    if (score >= 60) return "Good";
    if (score >= 45) return "Fair";
    return "Poor";
  };

  const purchaseLinks = [
    { name: "Namecheap", url: `https://www.namecheap.com/domains/registration/results/?domain=${domain.domainName}` },
    { name: "GoDaddy", url: `https://www.godaddy.com/domainsearch/find?domainToCheck=${domain.domainName}` },
    { name: "Porkbun", url: `https://porkbun.com/checkout/search?q=${domain.domainName}` },
  ];

  // Calculate score breakdown matching backend algorithm
  // Authority scoring (max 45 pts)
  const daScore = Math.min(18, metrics.domainAuthority >= 40 ? 18 :
    metrics.domainAuthority >= 20 ? 10 + ((metrics.domainAuthority - 20) / 20) * 8 :
    (metrics.domainAuthority / 20) * 10);
  const tfScore = Math.min(14, metrics.trustFlow >= 30 ? 14 :
    metrics.trustFlow >= 15 ? 8 + ((metrics.trustFlow - 15) / 15) * 6 :
    (metrics.trustFlow / 15) * 8);
  const cfScore = Math.min(8, metrics.citationFlow >= 40 ? 8 :
    metrics.citationFlow >= 20 ? 4 + ((metrics.citationFlow - 20) / 20) * 4 :
    (metrics.citationFlow / 20) * 4);
  let tfCfRatioBonus = 0;
  if (metrics.citationFlow > 0 && metrics.trustFlow > 0) {
    const ratio = metrics.trustFlow / metrics.citationFlow;
    tfCfRatioBonus = ratio >= 1.0 ? 5 : ratio >= 0.8 ? 4 : ratio >= 0.6 ? 2 : ratio >= 0.4 ? 1 : 0;
  }
  const authorityTotal = Math.round(daScore + tfScore + cfScore + tfCfRatioBonus);

  // Backlinks scoring (max 20 pts)
  const backlinksScore = metrics.backlinksCount > 0 ? Math.min(10, Math.log10(metrics.backlinksCount + 1) * 3.33) : 0;
  const domainPopVal = metrics.domainPop ?? Math.min(metrics.backlinksCount, 50);
  const domainPopScore = domainPopVal > 0 ? Math.min(10, Math.log10(domainPopVal + 1) * 4) : 0;
  const backlinksTotal = Math.round(backlinksScore + domainPopScore);

  // History scoring (max 20 pts)
  const ageYears = domainAge || 0;
  const ageScore = ageYears >= 15 ? 12 : ageYears >= 10 ? 9 + ((ageYears - 10) / 5) * 3 :
    ageYears >= 5 ? 5 + ((ageYears - 5) / 5) * 4 : (ageYears / 5) * 5;
  const archiveScore = metrics.archiveSnapshots >= 100 ? 8 :
    metrics.archiveSnapshots >= 50 ? 6 + ((metrics.archiveSnapshots - 50) / 50) * 2 :
    metrics.archiveSnapshots >= 20 ? 3 + ((metrics.archiveSnapshots - 20) / 30) * 3 :
    (metrics.archiveSnapshots / 20) * 3;
  const historyTotal = Math.round(ageScore + archiveScore);

  // Bonuses (max ~20 pts)
  const dictionaryBonus = metrics.isDictionaryWord ? 4 : 0;
  const cleanHistoryBonus = metrics.hasCleanHistory ? 4 : 0;
  const paBonus = Math.min(4, (metrics.pageAuthority / 100) * 4);
  const majesticRank = (metrics as any).majesticGlobalRank ?? 0;
  const majesticBonus = majesticRank > 0 && majesticRank < 1000000 ?
    (majesticRank < 100000 ? 4 : majesticRank < 500000 ? 3 : 2) : 0;
  const dmozBonus = (metrics as any).inDmoz ? 2 : 0;
  const wikiLinks = (metrics as any).wikipediaLinks ?? 0;
  const wikiBonus = Math.min(2, wikiLinks);
  const bonusesTotal = Math.round(dictionaryBonus + cleanHistoryBonus + paBonus + majesticBonus + dmozBonus + wikiBonus);

  const scoreBreakdown = [
    { label: "Authority (DA/TF/CF)", value: authorityTotal, max: 45 },
    { label: "Backlinks & Domain Pop", value: backlinksTotal, max: 20 },
    { label: "Age & Archive History", value: historyTotal, max: 20 },
    { label: "Bonuses", value: bonusesTotal, max: 20 },
  ];

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950">
      {/* Header */}
      <header className="bg-white dark:bg-zinc-900 border-b border-zinc-200 dark:border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <Button 
            variant="ghost" 
            onClick={() => setLocation("/")} 
            className="mb-4 -ml-2 text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Search
          </Button>
          
          <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-zinc-100 dark:bg-zinc-800">
                  <Globe className="h-5 w-5 text-zinc-600 dark:text-zinc-400" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold text-zinc-900 dark:text-white">
                    {domain.domainName}
                  </h1>
                  <div className="flex items-center gap-2 mt-1">
                    <Badge variant="outline" className="text-xs">.{domain.tld}</Badge>
                    <Badge 
                      variant="outline" 
                      className={`text-xs ${
                        domain.status === 'available' 
                          ? 'border-emerald-200 text-emerald-700 bg-emerald-50 dark:border-emerald-800 dark:text-emerald-400 dark:bg-emerald-900/20' 
                          : 'border-zinc-200 text-zinc-600'
                      }`}
                    >
                      {domain.status}
                    </Badge>
                    {domainAge && (
                      <Badge variant="outline" className="text-xs">
                        <Clock className="h-3 w-3 mr-1" />
                        {domainAge} years old
                      </Badge>
                    )}
                  </div>
                </div>
              </div>
            </div>
            
            <div className="flex flex-col items-start md:items-end">
              <div className="text-sm text-zinc-500 mb-1">Quality Score</div>
              <div className="flex items-center gap-3">
                <span className={`text-4xl font-bold ${getQualityColor(metrics.qualityScore)}`}>
                  {metrics.qualityScore}
                </span>
                <div className="text-right">
                  <Badge className={`${getQualityBg(metrics.qualityScore)} text-white`}>
                    {getQualityLabel(metrics.qualityScore)}
                  </Badge>
                  <p className="text-xs text-zinc-400 mt-1">out of 100</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-6">
            {/* Key Metrics */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <CardTitle className="text-base font-medium flex items-center gap-2">
                  <BarChart3 className="h-4 w-4" />
                  Key Metrics
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                  <div className="text-center p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-3xl font-bold text-zinc-900 dark:text-white">{metrics.domainAuthority}</p>
                    <p className="text-sm text-zinc-500 mt-1">Domain Authority</p>
                  </div>
                  <div className="text-center p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-3xl font-bold text-zinc-900 dark:text-white">{metrics.pageAuthority}</p>
                    <p className="text-sm text-zinc-500 mt-1">Page Authority</p>
                  </div>
                  <div className="text-center p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-3xl font-bold text-zinc-900 dark:text-white">{metrics.backlinksCount.toLocaleString()}</p>
                    <p className="text-sm text-zinc-500 mt-1">Backlinks</p>
                  </div>
                  <div className="text-center p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-3xl font-bold text-zinc-900 dark:text-white">{metrics.trustFlow}</p>
                    <p className="text-sm text-zinc-500 mt-1">Trust Flow</p>
                  </div>
                </div>

                <Separator className="my-6" />

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Citation Flow</span>
                    <span className="font-medium text-zinc-900 dark:text-white">{metrics.citationFlow}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Domain Pop</span>
                    <span className="font-medium text-zinc-900 dark:text-white">{metrics.domainPop}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Spam Score</span>
                    <span className={`font-medium ${metrics.spamScore > 30 ? 'text-red-600' : 'text-zinc-900 dark:text-white'}`}>
                      {metrics.spamScore}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Archive Snapshots</span>
                    <span className="font-medium text-zinc-900 dark:text-white">{metrics.archiveSnapshots}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Additional Metrics */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <CardTitle className="text-base font-medium flex items-center gap-2">
                  <TrendingUp className="h-4 w-4" />
                  Additional Metrics
                </CardTitle>
                <CardDescription>Extended domain data from ExpiredDomains.net</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-xs text-zinc-500 mb-1">Majestic Global Rank</p>
                    <p className="text-lg font-semibold text-zinc-900 dark:text-white">
                      {majesticRank > 0 ? majesticRank.toLocaleString() : '—'}
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-xs text-zinc-500 mb-1">In DMOZ</p>
                    <p className="text-lg font-semibold text-zinc-900 dark:text-white">
                      {(metrics as any).inDmoz ? (
                        <span className="text-emerald-600">Yes</span>
                      ) : (
                        <span className="text-zinc-400">No</span>
                      )}
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-xs text-zinc-500 mb-1">Wikipedia Links</p>
                    <p className="text-lg font-semibold text-zinc-900 dark:text-white">
                      {wikiLinks > 0 ? wikiLinks : '—'}
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-xs text-zinc-500 mb-1">Related Domains</p>
                    <p className="text-lg font-semibold text-zinc-900 dark:text-white">
                      {(metrics as any).relatedDomains || '—'}
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-xs text-zinc-500 mb-1">Registered TLDs</p>
                    <p className="text-lg font-semibold text-zinc-900 dark:text-white">
                      {(metrics as any).registeredTlds || '—'}
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <p className="text-xs text-zinc-500 mb-1">TF/CF Ratio</p>
                    <p className="text-lg font-semibold text-zinc-900 dark:text-white">
                      {metrics.citationFlow > 0
                        ? (metrics.trustFlow / metrics.citationFlow).toFixed(2)
                        : '—'}
                    </p>
                    {metrics.citationFlow > 0 && (
                      <p className="text-xs text-zinc-400">
                        {metrics.trustFlow / metrics.citationFlow >= 1.0 ? 'Excellent' :
                         metrics.trustFlow / metrics.citationFlow >= 0.8 ? 'Good' :
                         metrics.trustFlow / metrics.citationFlow >= 0.6 ? 'Fair' : 'Low'}
                      </p>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Score Breakdown */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <CardTitle className="text-base font-medium flex items-center gap-2">
                  <Zap className="h-4 w-4" />
                  Score Breakdown
                </CardTitle>
                <CardDescription>How the quality score is calculated</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {scoreBreakdown.map((item) => (
                  <div key={item.label} className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-zinc-600 dark:text-zinc-400">{item.label}</span>
                      <span className="font-medium text-zinc-900 dark:text-white">
                        {item.value}/{item.max} pts
                      </span>
                    </div>
                    <Progress value={(item.value / item.max) * 100} className="h-2" />
                  </div>
                ))}

                <Separator className="my-4" />

                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex flex-wrap items-center gap-2">
                    {metrics.isDictionaryWord && (
                      <Badge variant="outline" className="text-xs border-emerald-200 text-emerald-700 bg-emerald-50">
                        <CheckCircle2 className="h-3 w-3 mr-1" />
                        Dictionary Word (+4)
                      </Badge>
                    )}
                    {metrics.hasCleanHistory && (
                      <Badge variant="outline" className="text-xs border-emerald-200 text-emerald-700 bg-emerald-50">
                        <CheckCircle2 className="h-3 w-3 mr-1" />
                        Clean History (+4)
                      </Badge>
                    )}
                    {metrics.pageAuthority > 0 && (
                      <Badge variant="outline" className="text-xs border-blue-200 text-blue-700 bg-blue-50">
                        PA Bonus (+{Math.round(paBonus)})
                      </Badge>
                    )}
                    {majesticBonus > 0 && (
                      <Badge variant="outline" className="text-xs border-purple-200 text-purple-700 bg-purple-50">
                        Majestic Rank (+{majesticBonus})
                      </Badge>
                    )}
                    {dmozBonus > 0 && (
                      <Badge variant="outline" className="text-xs border-amber-200 text-amber-700 bg-amber-50">
                        DMOZ Listed (+{dmozBonus})
                      </Badge>
                    )}
                    {wikiBonus > 0 && (
                      <Badge variant="outline" className="text-xs border-cyan-200 text-cyan-700 bg-cyan-50">
                        Wikipedia (+{wikiBonus})
                      </Badge>
                    )}
                  </div>
                  <div className="text-right">
                    <span className="text-sm text-zinc-500">Total Score: </span>
                    <span className={`text-lg font-bold ${getQualityColor(metrics.qualityScore)}`}>
                      {metrics.qualityScore}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Historical Data */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <CardTitle className="text-base font-medium flex items-center gap-2">
                  <Archive className="h-4 w-4" />
                  Historical Data
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="flex items-start gap-4 p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <Calendar className="h-5 w-5 text-zinc-400 mt-0.5" />
                    <div>
                      <p className="text-sm text-zinc-500">Birth Year</p>
                      <p className="text-xl font-semibold text-zinc-900 dark:text-white">
                        {domain.birthYear || "Unknown"}
                      </p>
                      {domainAge && (
                        <p className="text-sm text-zinc-500 mt-1">{domainAge} years of history</p>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-start gap-4 p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                    <Archive className="h-5 w-5 text-zinc-400 mt-0.5" />
                    <div>
                      <p className="text-sm text-zinc-500">Archive Snapshots</p>
                      <p className="text-xl font-semibold text-zinc-900 dark:text-white">
                        {metrics.archiveSnapshots}
                      </p>
                      <a
                        href={`https://web.archive.org/web/*/${domain.domainName}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-blue-600 hover:underline mt-1 inline-flex items-center gap-1"
                      >
                        View on Archive.org
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Subdomain Discovery */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <CardTitle className="text-base font-medium flex items-center gap-2">
                      <Network className="h-4 w-4" />
                      Subdomain Discovery
                    </CardTitle>
                    <CardDescription>Find subdomains using multiple techniques</CardDescription>
                  </div>
                  <Button 
                    onClick={handleDiscoverSubdomains}
                    disabled={isDiscovering}
                    className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700"
                  >
                    {isDiscovering ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Discovering...
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4 mr-2" />
                        Discover Subdomains
                      </>
                    )}
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {/* Discovery Techniques Info */}
                {!subdomainResults && !isDiscovering && (
                  <div className="space-y-4">
                    <p className="text-sm text-zinc-500">
                      Click "Discover Subdomains" to scan for subdomains using:
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                        <span>DNS Records (NS, MX, TXT, CNAME)</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                        <span>DNS Enumeration (wordlist)</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                        <span>Certificate Transparency (crt.sh)</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                        <span>External APIs (HackerTarget)</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                        <span>Permutation Generation</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                        <span>IP Resolution</span>
                      </div>
                    </div>
                    <p className="text-xs text-zinc-400">
                      Job will be tracked in the Scraping Jobs section.
                    </p>
                  </div>
                )}

                {/* Loading State */}
                {isDiscovering && (
                  <div className="py-8 text-center">
                    <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-500" />
                    <p className="text-sm text-zinc-500">Discovering subdomains...</p>
                    <p className="text-xs text-zinc-400 mt-1">This may take a minute</p>
                  </div>
                )}

                {/* Results */}
                {subdomainResults && (
                  <div className="space-y-4">
                    {/* Summary */}
                    <div className="flex items-center justify-between p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                      <div>
                        <p className="text-2xl font-bold text-zinc-900 dark:text-white">
                          {subdomainResults.totalFound}
                        </p>
                        <p className="text-sm text-zinc-500">Subdomains Found</p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-zinc-500">Duration</p>
                        <p className="font-medium text-zinc-900 dark:text-white">
                          {(subdomainResults.duration / 1000).toFixed(1)}s
                        </p>
                      </div>
                    </div>

                    {/* Techniques Used */}
                    <div>
                      <p className="text-xs font-medium text-zinc-500 mb-2">Techniques Used:</p>
                      <div className="flex flex-wrap gap-1">
                        {subdomainResults.techniques.map((tech, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {tech}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {/* DNS Records */}
                    {(subdomainResults.dnsRecords.ns.length > 0 || 
                      subdomainResults.dnsRecords.mx.length > 0 || 
                      subdomainResults.dnsRecords.txt.length > 0) && (
                      <div>
                        <p className="text-xs font-medium text-zinc-500 mb-2">DNS Records:</p>
                        <div className="space-y-2 text-xs">
                          {subdomainResults.dnsRecords.ns.length > 0 && (
                            <div className="p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                              <span className="font-medium">NS:</span> {subdomainResults.dnsRecords.ns.join(', ')}
                            </div>
                          )}
                          {subdomainResults.dnsRecords.mx.length > 0 && (
                            <div className="p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                              <span className="font-medium">MX:</span> {subdomainResults.dnsRecords.mx.map(m => m.exchange).join(', ')}
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Subdomains Table */}
                    {subdomainResults.subdomains.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-zinc-500 mb-2">Discovered Subdomains:</p>
                        <ScrollArea className="h-[260px] sm:h-[300px] border rounded-lg">
                          <Table className="min-w-[520px]">
                            <TableHeader>
                              <TableRow>
                                <TableHead>Subdomain</TableHead>
                                <TableHead>IP Address</TableHead>
                                <TableHead>Source</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {subdomainResults.subdomains.map((sub, i) => (
                                <TableRow key={i}>
                                  <TableCell className="font-mono text-xs">
                                    {sub.subdomain}
                                  </TableCell>
                                  <TableCell className="font-mono text-xs text-zinc-500">
                                    {sub.ip || '—'}
                                  </TableCell>
                                  <TableCell>
                                    <Badge variant="outline" className="text-xs">
                                      {sub.source}
                                    </Badge>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </ScrollArea>
                      </div>
                    )}

                    {subdomainResults.subdomains.length === 0 && (
                      <div className="py-4 text-center text-zinc-500">
                        <Server className="h-8 w-8 mx-auto mb-2 text-zinc-300" />
                        <p className="text-sm">No subdomains found</p>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Backlink Analysis */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <CardTitle className="text-base font-medium flex items-center gap-2">
                      <LinkIcon className="h-4 w-4" />
                      Backlink Profile
                    </CardTitle>
                    <CardDescription>Analyze referring domains and anchor texts</CardDescription>
                  </div>
                  <Button 
                    onClick={handleAnalyzeBacklinks}
                    disabled={isAnalyzingBacklinks}
                    className="w-full sm:w-auto bg-purple-600 hover:bg-purple-700"
                  >
                    {isAnalyzingBacklinks ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <LinkIcon className="h-4 w-4 mr-2" />
                        Analyze Backlinks
                      </>
                    )}
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {/* Initial State */}
                {!backlinkResults && !isAnalyzingBacklinks && (
                  <div className="space-y-4">
                    <p className="text-sm text-zinc-500">
                      Click "Analyze Backlinks" to fetch backlink data from:
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-purple-500" />
                        <span>OpenLinkProfiler</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-purple-500" />
                        <span>CommonCrawl Index</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-purple-500" />
                        <span>Archive.org Wayback</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded">
                        <CheckCircle2 className="h-3 w-3 text-purple-500" />
                        <span>Anchor Text Analysis</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Loading State */}
                {isAnalyzingBacklinks && (
                  <div className="py-8 text-center">
                    <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-purple-500" />
                    <p className="text-sm text-zinc-500">Analyzing backlinks...</p>
                    <p className="text-xs text-zinc-400 mt-1">This may take a minute</p>
                  </div>
                )}

                {/* Results */}
                {backlinkResults && (
                  <div className="space-y-4">
                    {/* Summary Stats */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg text-center">
                        <p className="text-2xl font-bold text-zinc-900 dark:text-white">
                          {backlinkResults.totalBacklinks}
                        </p>
                        <p className="text-xs text-zinc-500">Backlinks</p>
                      </div>
                      <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg text-center">
                        <p className="text-2xl font-bold text-zinc-900 dark:text-white">
                          {backlinkResults.uniqueDomains}
                        </p>
                        <p className="text-xs text-zinc-500">Linking Domains</p>
                      </div>
                      <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg text-center">
                        <p className="text-2xl font-bold text-emerald-600">
                          {backlinkResults.dofollowPercent}%
                        </p>
                        <p className="text-xs text-zinc-500">Dofollow</p>
                      </div>
                      <div className="p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg text-center">
                        <p className="text-2xl font-bold text-amber-600">
                          {backlinkResults.nofollowPercent}%
                        </p>
                        <p className="text-xs text-zinc-500">Nofollow</p>
                      </div>
                    </div>

                    {/* Data Sources */}
                    {backlinkResults.sources && backlinkResults.sources.length > 0 && (
                      <div className="flex items-center gap-2 text-xs text-zinc-500">
                        <span>Data from:</span>
                        {backlinkResults.sources.map((source, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {source}
                          </Badge>
                        ))}
                      </div>
                    )}

                    {/* Top Referring Domains */}
                    {backlinkResults.topReferringDomains.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-zinc-500 mb-2">Top Referring Domains:</p>
                        <div className="space-y-1">
                          {backlinkResults.topReferringDomains.slice(0, 5).map((ref, i) => (
                            <div key={i} className="flex items-center justify-between p-2 bg-zinc-50 dark:bg-zinc-800/50 rounded text-xs">
                              <span className="font-mono truncate max-w-[200px]">{ref.domain}</span>
                              <Badge variant="outline" className="text-xs">
                                {ref.count} links
                              </Badge>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Backlinks Table */}
                    {backlinkResults.backlinks.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-zinc-500 mb-2">Backlinks:</p>
                        <ScrollArea className="h-[260px] sm:h-[300px] border rounded-lg">
                          <Table className="min-w-[720px]">
                            <TableHeader>
                              <TableRow>
                                <TableHead>DR</TableHead>
                                <TableHead>Referring Page</TableHead>
                                <TableHead>Anchor & Target</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {backlinkResults.backlinks.map((bl, i) => (
                                <TableRow key={i}>
                                  <TableCell className="font-bold text-center">
                                    {bl.domainRating || '—'}
                                  </TableCell>
                                  <TableCell>
                                    <div className="max-w-[200px]">
                                      <a 
                                        href={bl.sourceUrl} 
                                        target="_blank" 
                                        rel="noopener noreferrer"
                                        className="text-xs text-blue-600 hover:underline truncate block"
                                      >
                                        {bl.sourceUrl}
                                      </a>
                                    </div>
                                  </TableCell>
                                  <TableCell>
                                    <div className="text-xs">
                                      <span className="text-emerald-600">{bl.anchorText || '(no anchor)'}</span>
                                      <br />
                                      <span className="text-zinc-400 truncate block max-w-[150px]">{bl.targetUrl}</span>
                                    </div>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </ScrollArea>
                      </div>
                    )}

                    {backlinkResults.backlinks.length === 0 && (
                      <div className="py-4 text-center text-zinc-500">
                        <LinkIcon className="h-8 w-8 mx-auto mb-2 text-zinc-300" />
                        <p className="text-sm">No backlinks found</p>
                        {backlinkResults.message && (
                          <p className="text-xs text-amber-600 mt-2 px-4">
                            {backlinkResults.message}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Purchase Options */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <CardTitle className="text-base font-medium flex items-center gap-2">
                  <Link2 className="h-4 w-4" />
                  Register Domain
                </CardTitle>
                <CardDescription>Check availability and register</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {purchaseLinks.map((link) => (
                  <Button
                    key={link.name}
                    variant="outline"
                    className="w-full justify-between"
                    asChild
                  >
                    <a href={link.url} target="_blank" rel="noopener noreferrer">
                      <span>{link.name}</span>
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </Button>
                ))}
              </CardContent>
            </Card>

            {/* Quality Indicators */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <CardTitle className="text-base font-medium flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Quality Indicators
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-zinc-600 dark:text-zinc-400">Dictionary Word</span>
                  {metrics.isDictionaryWord ? (
                    <Badge className="bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-400 dark:border-emerald-800">Yes</Badge>
                  ) : (
                    <Badge variant="outline">No</Badge>
                  )}
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-sm text-zinc-600 dark:text-zinc-400">Clean History</span>
                    <p className="text-[10px] text-zinc-400 dark:text-zinc-500">Quality 45+ & no spam</p>
                  </div>
                  {metrics.hasCleanHistory && metrics.qualityScore >= 45 ? (
                    <Badge className="bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-400 dark:border-emerald-800">
                      <CheckCircle2 className="h-3 w-3 mr-1" />
                      Clean
                    </Badge>
                  ) : (
                    <Badge className="bg-red-50 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800">
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      {metrics.qualityScore < 45 ? "Low Quality" : "Issues Found"}
                    </Badge>
                  )}
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-sm text-zinc-600 dark:text-zinc-400">Security Check</span>
                    <p className="text-[10px] text-zinc-400 dark:text-zinc-500">Spam/malware scan</p>
                  </div>
                  {metrics.spamScore === 0 ? (
                    <Badge className="bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700">
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      Not Checked
                    </Badge>
                  ) : metrics.spamScore <= 10 ? (
                    <Badge className="bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-400 dark:border-emerald-800">
                      <CheckCircle2 className="h-3 w-3 mr-1" />
                      Safe
                    </Badge>
                  ) : metrics.spamScore <= 30 ? (
                    <Badge className="bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-800">
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      Moderate Risk
                    </Badge>
                  ) : (
                    <Badge className="bg-red-50 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800">
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      High Risk
                    </Badge>
                  )}
                </div>
                {metrics.spamScore === 0 && (
                  <div className="p-2 bg-amber-50 dark:bg-amber-900/20 rounded text-xs text-amber-700 dark:text-amber-400">
                    ⚠️ Configure API keys in Settings to enable security checks (Spamhaus, Google Safe Browsing, VirusTotal)
                  </div>
                )}
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-zinc-600 dark:text-zinc-400">Risk Score</span>
                  <Badge 
                    className={
                      metrics.spamScore === 0
                        ? "bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700"
                        : metrics.spamScore <= 10 
                        ? "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-400 dark:border-emerald-800" 
                        : metrics.spamScore <= 30 
                        ? "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-800"
                        : "bg-red-50 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800"
                    }
                  >
                    {metrics.spamScore === 0 ? "N/A" : `${metrics.spamScore}%`}
                  </Badge>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-zinc-600 dark:text-zinc-400">Last Checked</span>
                  <span className="text-sm text-zinc-900 dark:text-white">
                    {new Date(metrics.lastChecked).toLocaleDateString()}
                  </span>
                </div>
              </CardContent>
            </Card>

            {/* Domain Info */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="pb-4">
                <CardTitle className="text-base font-medium flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  Domain Info
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-zinc-500">Domain Name</span>
                  <span className="font-medium text-zinc-900 dark:text-white">{domain.domainName}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">TLD</span>
                  <span className="font-medium text-zinc-900 dark:text-white">.{domain.tld}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Status</span>
                  <span className="font-medium text-zinc-900 dark:text-white capitalize">{domain.status}</span>
                </div>
                {domain.droppedDate && (
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Dropped Date</span>
                    <span className="font-medium text-zinc-900 dark:text-white">
                      {new Date(domain.droppedDate).toLocaleDateString()}
                    </span>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}

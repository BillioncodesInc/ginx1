import { useState, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import {
  Loader2, Search, Sparkles, SlidersHorizontal, FileDown,
  Settings, Play, Database, Globe, TrendingUp, Zap,
  ChevronRight, ExternalLink, RefreshCw, CheckCircle2, XCircle, Clock, Eye, X
} from "lucide-react";
import { MangoTreeSketch } from "@/components/MangoTreeSketch";
import { ScrapingJobsTable } from "@/components/ScrapingJobsTable";
import { SettingsDialog } from "@/components/SettingsDialog";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { DomainResult } from "@/types/domain";

// Session storage keys for persisting search state
const STORAGE_KEYS = {
  keyword: 'domainHunter_keyword',
  searchResults: 'domainHunter_searchResults',
  searchFromCache: 'domainHunter_searchFromCache',
  filters: 'domainHunter_filters',
};

// Helper to safely parse JSON from sessionStorage
function getStoredValue<T>(key: string, defaultValue: T): T {
  try {
    const stored = sessionStorage.getItem(key);
    return stored ? JSON.parse(stored) : defaultValue;
  } catch {
    return defaultValue;
  }
}

// Generate UUID that works in non-secure contexts (HTTP)
function generateUUID(): string {
  // Try crypto.randomUUID first (only works in secure contexts - HTTPS)
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
  } catch {
    // crypto.randomUUID not available in non-secure context
  }
  // Fallback for non-secure contexts (HTTP) - uses Math.random()
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

const defaultFilters = {
  minBacklinks: 0,
  minTrustFlow: 0,
  minCitationFlow: 0,
  minAge: 0,
  maxAge: 30,
  minArchiveSnapshots: 0,
  minDomainPop: 0,
  minDA: 0,
  maxSpamScore: 100,
  minLength: 0,
  maxLength: 63,
  dictionaryOnly: false,
};

export default function Home() {
  // Initialize state from sessionStorage to persist across navigation
  const [keyword, setKeyword] = useState(() => getStoredValue(STORAGE_KEYS.keyword, ""));
  const [showFilters, setShowFilters] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [filters, setFilters] = useState(() => getStoredValue(STORAGE_KEYS.filters, defaultFilters));
  const [quickFindTriggered, setQuickFindTriggered] = useState(false);
  const [activeTab, setActiveTab] = useState("search");
  const [visualizationData, setVisualizationData] = useState<DomainResult[] | null>(null);
  const [visualizationSource, setVisualizationSource] = useState<string>("");
  const [searchResults, setSearchResults] = useState<any[] | null>(() => getStoredValue(STORAGE_KEYS.searchResults, null));
  const [keywordError, setKeywordError] = useState<string | null>(null);
  const [activeSearchId, setActiveSearchId] = useState<string | null>(null);
  const [searchFromCache, setSearchFromCache] = useState(() => getStoredValue(STORAGE_KEYS.searchFromCache, false));
  const [searchProgress, setSearchProgress] = useState(0);
  const [searchStage, setSearchStage] = useState<'starting' | 'scraping' | 'enriching' | 'finishing'>('starting');

  // Persist search state to sessionStorage
  useEffect(() => {
    sessionStorage.setItem(STORAGE_KEYS.keyword, JSON.stringify(keyword));
  }, [keyword]);

  useEffect(() => {
    sessionStorage.setItem(STORAGE_KEYS.searchResults, JSON.stringify(searchResults));
  }, [searchResults]);

  useEffect(() => {
    sessionStorage.setItem(STORAGE_KEYS.searchFromCache, JSON.stringify(searchFromCache));
  }, [searchFromCache]);

  useEffect(() => {
    sessionStorage.setItem(STORAGE_KEYS.filters, JSON.stringify(filters));
  }, [filters]);

  // Stats query
  const statsQuery = trpc.stats.getDashboardStats.useQuery();

  // Jobs query
  const jobsQuery = trpc.domains.getJobs.useQuery({ limit: 20 });

  // Live search mutation - scrapes expireddomains.net
  const searchMutation = trpc.domains.search.useMutation({
    onSuccess: (data) => {
      setSearchResults(data.results);
      setSearchFromCache(data.fromCache);
      setActiveSearchId(null);
      if (data.results.length > 0) {
        const cacheMsg = data.fromCache ? ' (from cache)' : '';
        toast.success(`Found ${data.results.length} domains for "${keyword}"${cacheMsg}`);
      } else {
        toast.info(`No domains found for "${keyword}"`);
      }
    },
    onError: (error) => {
      toast.error(error.message);
      setSearchResults(null);
      setActiveSearchId(null);
    },
  });

  // Cancel search mutation
  const cancelSearchMutation = trpc.domains.cancelSearch.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.info('Search cancelled');
        setActiveSearchId(null);
      }
    },
  });

  // Simulate progress stages during search
  useEffect(() => {
    if (!searchMutation.isPending) {
      setSearchProgress(0);
      setSearchStage('starting');
      return;
    }

    // Progress simulation based on typical search timing
    const stages = [
      { time: 0, progress: 5, stage: 'starting' as const },
      { time: 2000, progress: 15, stage: 'scraping' as const },
      { time: 5000, progress: 35, stage: 'scraping' as const },
      { time: 10000, progress: 55, stage: 'enriching' as const },
      { time: 15000, progress: 70, stage: 'enriching' as const },
      { time: 20000, progress: 85, stage: 'finishing' as const },
      { time: 25000, progress: 95, stage: 'finishing' as const },
    ];

    const timeouts: NodeJS.Timeout[] = [];
    stages.forEach(({ time, progress, stage }) => {
      const timeout = setTimeout(() => {
        setSearchProgress(progress);
        setSearchStage(stage);
      }, time);
      timeouts.push(timeout);
    });

    return () => timeouts.forEach(t => clearTimeout(t));
  }, [searchMutation.isPending]);

  // Quick find query - searches existing database
  const quickFindQuery = trpc.domains.quickFind.useQuery(
    { limit: 30 },
    { enabled: quickFindTriggered }
  );

  // Scraping mutation
  const scrapeMutation = trpc.domains.scrape.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(data.message);
        jobsQuery.refetch();
      } else {
        toast.error(data.message);
      }
    },
    onError: (error) => {
      toast.error(`Scraping failed: ${error.message}`);
    },
  });

  // Validate keyword input
  const validateKeyword = (value: string): string | null => {
    if (value.length < 2) {
      return "Enter at least 2 characters";
    }
    if (value.length > 63) {
      return "Search term is too long (max 63 characters)";
    }
    if (!/^[a-zA-Z0-9-]+$/.test(value)) {
      return "Only letters, numbers, and hyphens are allowed";
    }
    return null;
  };

  const handleSearch = (forceRefresh = false) => {
    // Validate input
    const error = validateKeyword(keyword);
    if (error) {
      setKeywordError(error);
      toast.error(error);
      return;
    }
    setKeywordError(null);
    setQuickFindTriggered(false);
    setSearchResults(null);
    setSearchFromCache(false);

    // Generate search ID for tracking/cancellation
    const searchId = generateUUID();
    setActiveSearchId(searchId);

    // Trigger live scraping
    searchMutation.mutate({ keyword, maxPages: 1, searchId, forceRefresh });
  };

  const handleCancelSearch = () => {
    if (activeSearchId) {
      cancelSearchMutation.mutate({ searchId: activeSearchId });
    }
  };

  const handleQuickFind = () => {
    setKeywordError(null);
    setSearchResults(null);
    setQuickFindTriggered(true);
  };

  const handleScrape = () => {
    scrapeMutation.mutate({ maxPages: 3 });
  };

  // Display results: search results (from live scrape) or quick find (from DB)
  const rawResults = searchResults ?? (quickFindTriggered ? quickFindQuery.data : null);
  const isLoading = searchMutation.isPending || (quickFindTriggered && quickFindQuery.isLoading);

  // Apply filters to results
  const displayResults = rawResults?.filter((result) => {
    const currentYear = new Date().getFullYear();
    const age = result.domain.birthYear ? currentYear - result.domain.birthYear : 0;
    const domainLength = result.domain.length ?? result.domain.domainName.split('.')[0].length;

    if (result.metrics.backlinksCount < filters.minBacklinks) return false;
    if ((result.metrics.domainPop ?? 0) < filters.minDomainPop) return false;
    if (result.metrics.trustFlow < filters.minTrustFlow) return false;
    if (result.metrics.citationFlow < filters.minCitationFlow) return false;
    if (result.metrics.domainAuthority < filters.minDA) return false;
    if ((result.metrics.spamScore ?? 0) > filters.maxSpamScore) return false;
    if ((result.metrics.archiveSnapshots ?? 0) < filters.minArchiveSnapshots) return false;
    if (result.domain.birthYear && (age < filters.minAge || age > filters.maxAge)) return false;
    if (domainLength < filters.minLength || domainLength > filters.maxLength) return false;

    return true;
  }) ?? null;

  // Handler to visualize search results
  const handleVisualizeSearchResults = () => {
    if (displayResults && displayResults.length > 0) {
      // Transform to DomainResult format for MangoTreeSketch
      const visualData: DomainResult[] = displayResults.map((r) => ({
        domain: {
          id: r.domain.id,
          domainName: r.domain.domainName,
          tld: r.domain.tld,
          birthYear: r.domain.birthYear,
        },
        metrics: {
          qualityScore: r.metrics.qualityScore,
          domainAuthority: r.metrics.domainAuthority,
          pageAuthority: r.metrics.pageAuthority,
          backlinksCount: r.metrics.backlinksCount,
          trustFlow: r.metrics.trustFlow,
          citationFlow: r.metrics.citationFlow,
        },
      }));
      setVisualizationData(visualData);
      setVisualizationSource(quickFindTriggered ? "Quick Find Results" : "Search Results");
      setActiveTab("visualization");
      toast.success(`Visualizing ${displayResults.length} domains`);
    }
  };

  // Handler to visualize job results (passed to ScrapingJobsTable)
  const handleVisualizeJobResults = (jobName: string, results: Array<{
    domainName: string;
    tld: string;
    birthYear?: number;
    backlinksCount?: number;
    domainAuthority?: number;
    trustFlow?: number;
    qualityScore?: number;
  }>) => {
    // Convert job results to DomainResult format
    const visualData: DomainResult[] = results.map((r, idx) => ({
      domain: {
        id: idx, // Use index as temporary ID since job results don't have real IDs
        domainName: r.domainName,
        tld: r.tld,
        birthYear: r.birthYear ?? null,
      },
      metrics: {
        qualityScore: r.qualityScore ?? 0,
        domainAuthority: r.domainAuthority ?? 0,
        pageAuthority: 0,
        backlinksCount: r.backlinksCount ?? 0,
        trustFlow: r.trustFlow ?? 0,
        citationFlow: 0,
      },
    }));

    setVisualizationData(visualData);
    setVisualizationSource(`Job: ${jobName}`);
    setActiveTab("visualization");
    toast.success(`Visualizing ${results.length} domains from ${jobName}`);
  };

  // Data for visualization - only use the explicit visualization data
  const visualizationDomains: DomainResult[] = visualizationData ?? [];

  const exportToCSV = () => {
    if (!displayResults || displayResults.length === 0) {
      toast.error("No data to export");
      return;
    }

    const headers = [
      "Domain Name", "TLD", "Quality Score", "Domain Authority", "Page Authority",
      "Backlinks", "Trust Flow", "Citation Flow", "Domain Pop", "Archive Snapshots",
      "Spam Score", "Birth Year", "Age (Years)", "Status", "Dropped Date",
    ];

    const currentYear = new Date().getFullYear();
    const rows = displayResults.map((result) => {
      const age = result.domain.birthYear ? currentYear - result.domain.birthYear : "N/A";
      const droppedDate = result.domain.droppedDate
        ? new Date(result.domain.droppedDate).toLocaleDateString()
        : "N/A";

      return [
        result.domain.domainName, result.domain.tld, result.metrics.qualityScore,
        result.metrics.domainAuthority, result.metrics.pageAuthority || 0,
        result.metrics.backlinksCount, result.metrics.trustFlow, result.metrics.citationFlow,
        result.metrics.domainPop, result.metrics.archiveSnapshots, result.metrics.spamScore,
        result.domain.birthYear || "N/A", age, result.domain.status, droppedDate,
      ];
    });

    const csvContent = [
      headers.join(","),
      ...rows.map((row) => row.map((cell) => `"${cell}"`).join(",")),
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `domains-${new Date().toISOString().split("T")[0]}.csv`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    toast.success(`Exported ${displayResults.length} domains to CSV`);
  };

  const getQualityBadge = (score: number) => {
    if (score >= 75) return <Badge className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">Excellent</Badge>;
    if (score >= 60) return <Badge className="bg-blue-500/10 text-blue-600 border-blue-500/20">Good</Badge>;
    if (score >= 45) return <Badge className="bg-amber-500/10 text-amber-600 border-amber-500/20">Fair</Badge>;
    return <Badge className="bg-red-500/10 text-red-600 border-red-500/20">Poor</Badge>;
  };

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950">
      {/* Header */}
      <header className="bg-white dark:bg-zinc-900 border-b border-zinc-200 dark:border-zinc-800 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14 sm:h-16">
            <div className="flex items-center gap-2 sm:gap-3 min-w-0">
              <div className="flex items-center justify-center w-8 h-8 sm:w-9 sm:h-9 rounded-lg bg-zinc-900 dark:bg-white flex-shrink-0">
                <Globe className="h-4 w-4 sm:h-5 sm:w-5 text-white dark:text-zinc-900" />
              </div>
              <div className="min-w-0">
                <h1 className="text-sm sm:text-lg font-semibold text-zinc-900 dark:text-white truncate">
                  Domain Hunter Pro
                </h1>
                <p className="text-[10px] sm:text-xs text-zinc-500 hidden xs:block">Expired Domain Discovery</p>
              </div>
            </div>

            <div className="flex items-center gap-1 sm:gap-2 flex-shrink-0">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSettingsOpen(true)}
                className="h-8 sm:h-9 px-2 sm:px-3"
              >
                <Settings className="h-4 w-4 sm:mr-2" />
                <span className="hidden sm:inline">Settings</span>
              </Button>
              <Button
                onClick={handleScrape}
                disabled={scrapeMutation.isPending}
                size="sm"
                className="h-8 sm:h-9 px-2 sm:px-3 bg-zinc-900 hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100"
              >
                {scrapeMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 sm:mr-2 animate-spin" />
                    <span className="hidden sm:inline">Scraping...</span>
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 sm:mr-2" />
                    <span className="hidden sm:inline">Run Scraper</span>
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8 py-4 sm:py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 xs:grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4 mb-4 sm:mb-8">
          <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div className="min-w-0">
                  <p className="text-[10px] sm:text-sm text-zinc-500 dark:text-zinc-400">Total Domains</p>
                  <p className="text-lg sm:text-2xl font-bold text-zinc-900 dark:text-white mt-0.5 sm:mt-1 truncate">
                    {statsQuery.data?.totalDomains?.toLocaleString() ?? "—"}
                  </p>
                </div>
                <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-full bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center flex-shrink-0">
                  <Database className="h-4 w-4 sm:h-5 sm:w-5 text-zinc-600 dark:text-zinc-400" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div className="min-w-0">
                  <p className="text-[10px] sm:text-sm text-zinc-500 dark:text-zinc-400">High Quality</p>
                  <p className="text-lg sm:text-2xl font-bold text-emerald-600 mt-0.5 sm:mt-1 truncate">
                    {statsQuery.data?.highQualityCount?.toLocaleString() ?? "—"}
                  </p>
                </div>
                <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-full bg-emerald-50 dark:bg-emerald-900/20 flex items-center justify-center flex-shrink-0">
                  <Zap className="h-4 w-4 sm:h-5 sm:w-5 text-emerald-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div className="min-w-0">
                  <p className="text-[10px] sm:text-sm text-zinc-500 dark:text-zinc-400">Avg Trust Flow</p>
                  <p className="text-lg sm:text-2xl font-bold text-blue-600 mt-0.5 sm:mt-1 truncate">
                    {statsQuery.data?.avgTrustFlow ?? "—"}
                  </p>
                </div>
                <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-full bg-blue-50 dark:bg-blue-900/20 flex items-center justify-center flex-shrink-0">
                  <TrendingUp className="h-4 w-4 sm:h-5 sm:w-5 text-blue-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div className="min-w-0">
                  <p className="text-[10px] sm:text-sm text-zinc-500 dark:text-zinc-400">Last Scan</p>
                  <p className="text-lg sm:text-2xl font-bold text-zinc-900 dark:text-white mt-0.5 sm:mt-1 truncate">
                    {statsQuery.data?.lastScanTime ?? "—"}
                  </p>
                </div>
                <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-full bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center flex-shrink-0">
                  <Clock className="h-4 w-4 sm:h-5 sm:w-5 text-zinc-600 dark:text-zinc-400" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4 sm:space-y-6">
          <div className="overflow-x-auto -mx-4 px-4 sm:mx-0 sm:px-0">
            <TabsList className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-1 h-auto inline-flex w-auto min-w-full sm:w-auto">
              <TabsTrigger
                value="search"
                className="data-[state=active]:bg-zinc-100 dark:data-[state=active]:bg-zinc-800 px-3 sm:px-4 py-2 text-xs sm:text-sm whitespace-nowrap"
              >
                <Search className="h-4 w-4 mr-1 sm:mr-2" />
                <span className="hidden xs:inline">Search</span> Domains
              </TabsTrigger>
              <TabsTrigger
                value="visualization"
                className="data-[state=active]:bg-zinc-100 dark:data-[state=active]:bg-zinc-800 px-3 sm:px-4 py-2 text-xs sm:text-sm whitespace-nowrap"
              >
                <Globe className="h-4 w-4 mr-1 sm:mr-2" />
                Network<span className="hidden xs:inline"> View</span>
                {visualizationData && visualizationData.length > 0 && (
                  <Badge variant="secondary" className="ml-1 sm:ml-2 text-[10px] sm:text-xs">
                    {visualizationData.length}
                  </Badge>
                )}
              </TabsTrigger>
              <TabsTrigger
                value="jobs"
                className="data-[state=active]:bg-zinc-100 dark:data-[state=active]:bg-zinc-800 px-3 sm:px-4 py-2 text-xs sm:text-sm whitespace-nowrap"
              >
                <RefreshCw className="h-4 w-4 mr-1 sm:mr-2" />
                <span className="hidden xs:inline">Scraping</span> Jobs
              </TabsTrigger>
            </TabsList>
          </div>

          {/* Search Tab */}
          <TabsContent value="search" className="space-y-6">
            {/* Search Controls */}
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardContent className="p-6">
                <div className="flex flex-col sm:flex-row gap-3 w-full">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                    <Input
                      placeholder="Enter keyword to search expired domains (e.g., crypto, tech, shop)"
                      value={keyword}
                      onChange={(e) => {
                        setKeyword(e.target.value);
                        setKeywordError(null);
                      }}
                      onKeyDown={(e) => e.key === "Enter" && handleSearch(false)}
                      className={`pl-10 h-11 bg-zinc-50 dark:bg-zinc-800 border-zinc-200 dark:border-zinc-700 ${
                        keywordError ? 'border-red-500 focus:ring-red-500' : ''
                      }`}
                    />
                    {keywordError && (
                      <p className="absolute -bottom-5 left-0 text-xs text-red-500">{keywordError}</p>
                    )}
                  </div>
                  <Button
                    onClick={() => handleSearch(false)}
                    disabled={searchMutation.isPending || !keyword.trim()}
                    className="w-full sm:w-auto h-11 px-6 bg-zinc-900 hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100"
                  >
                    {searchMutation.isPending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Search className="h-4 w-4 mr-2" />
                    )}
                    {searchMutation.isPending ? 'Scraping...' : 'Search'}
                  </Button>
                  <Button
                    onClick={handleQuickFind}
                    variant="outline"
                    disabled={quickFindQuery.isLoading}
                    className="w-full sm:w-auto h-11 px-6"
                    title="Browse high-quality domains from database"
                  >
                    {quickFindQuery.isLoading && quickFindTriggered ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Database className="h-4 w-4 mr-2" />
                    )}
                    Quick Find
                  </Button>
                </div>
                <p className="text-xs text-zinc-500 mt-2">
                  <span className="font-medium">Search:</span> Live scrapes expireddomains.net for your keyword |
                  <span className="font-medium ml-1">Quick Find:</span> Browse cached high-quality domains
                </p>

                <Collapsible open={showFilters} onOpenChange={setShowFilters} className="mt-4">
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" size="sm" className="text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white">
                      <SlidersHorizontal className="h-4 w-4 mr-2" />
                      {showFilters ? "Hide Filters" : "Show Filters"}
                      <ChevronRight className={`h-4 w-4 ml-2 transition-transform ${showFilters ? 'rotate-90' : ''}`} />
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-4">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
                      {/* Row 1: Backlinks, Domain Pop, Trust Flow, Citation Flow */}
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Min Backlinks: <span className="font-semibold text-zinc-900 dark:text-white">{filters.minBacklinks}</span>
                        </Label>
                        <Slider
                          value={[filters.minBacklinks]}
                          onValueChange={([value]) => setFilters((f) => ({ ...f, minBacklinks: value }))}
                          max={500}
                          step={10}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Min Domain Pop: <span className="font-semibold text-zinc-900 dark:text-white">{filters.minDomainPop}</span>
                        </Label>
                        <Slider
                          value={[filters.minDomainPop]}
                          onValueChange={([value]) => setFilters((f) => ({ ...f, minDomainPop: value }))}
                          max={100}
                          step={5}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Min Trust Flow: <span className="font-semibold text-zinc-900 dark:text-white">{filters.minTrustFlow}</span>
                        </Label>
                        <Slider
                          value={[filters.minTrustFlow]}
                          onValueChange={([value]) => setFilters((f) => ({ ...f, minTrustFlow: value }))}
                          max={100}
                          step={5}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Min Citation Flow: <span className="font-semibold text-zinc-900 dark:text-white">{filters.minCitationFlow}</span>
                        </Label>
                        <Slider
                          value={[filters.minCitationFlow]}
                          onValueChange={([value]) => setFilters((f) => ({ ...f, minCitationFlow: value }))}
                          max={100}
                          step={5}
                        />
                      </div>

                      {/* Row 2: DA, Age Range, Spam Score */}
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Min DA: <span className="font-semibold text-zinc-900 dark:text-white">{filters.minDA}</span>
                        </Label>
                        <Slider
                          value={[filters.minDA]}
                          onValueChange={([value]) => setFilters((f) => ({ ...f, minDA: value }))}
                          max={100}
                          step={5}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Age: <span className="font-semibold text-zinc-900 dark:text-white">{filters.minAge}-{filters.maxAge} years</span>
                        </Label>
                        <Slider
                          value={[filters.minAge, filters.maxAge]}
                          onValueChange={([min, max]) => setFilters((f) => ({ ...f, minAge: min, maxAge: max }))}
                          max={30}
                          step={1}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Max Spam Score: <span className="font-semibold text-zinc-900 dark:text-white">{filters.maxSpamScore}</span>
                        </Label>
                        <Slider
                          value={[filters.maxSpamScore]}
                          onValueChange={([value]) => setFilters((f) => ({ ...f, maxSpamScore: value }))}
                          max={100}
                          step={5}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Min Archive Snapshots: <span className="font-semibold text-zinc-900 dark:text-white">{filters.minArchiveSnapshots}</span>
                        </Label>
                        <Slider
                          value={[filters.minArchiveSnapshots]}
                          onValueChange={([value]) => setFilters((f) => ({ ...f, minArchiveSnapshots: value }))}
                          max={100}
                          step={5}
                        />
                      </div>

                      {/* Row 3: Length Range, Dictionary Toggle */}
                      <div className="space-y-2">
                        <Label className="text-xs text-zinc-600 dark:text-zinc-400">
                          Domain Length: <span className="font-semibold text-zinc-900 dark:text-white">{filters.minLength}-{filters.maxLength} chars</span>
                        </Label>
                        <Slider
                          value={[filters.minLength, filters.maxLength]}
                          onValueChange={([min, max]) => setFilters((f) => ({ ...f, minLength: min, maxLength: max }))}
                          max={63}
                          step={1}
                        />
                      </div>
                      <div className="flex items-center space-x-3 pt-4">
                        <Switch
                          id="dictionary"
                          checked={filters.dictionaryOnly}
                          onCheckedChange={(checked) => setFilters((f) => ({ ...f, dictionaryOnly: checked }))}
                        />
                        <Label htmlFor="dictionary" className="text-xs text-zinc-600 dark:text-zinc-400">
                          Dictionary words only
                        </Label>
                      </div>
                      <div className="col-span-2 flex items-center justify-end pt-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setFilters(defaultFilters)}
                          className="text-xs"
                        >
                          Reset Filters
                        </Button>
                      </div>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>

            {/* Results Table */}
            {searchMutation.isPending ? (
              <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
                <CardContent className="py-12">
                  <div className="flex flex-col items-center justify-center max-w-md mx-auto">
                    <Loader2 className="h-10 w-10 animate-spin text-blue-500 mb-4" />
                    <p className="text-lg font-medium text-zinc-900 dark:text-white mb-2">
                      {searchStage === 'starting' && 'Initializing search...'}
                      {searchStage === 'scraping' && `Scraping domains for "${keyword}"...`}
                      {searchStage === 'enriching' && 'Enriching with quality metrics...'}
                      {searchStage === 'finishing' && 'Finalizing results...'}
                    </p>

                    {/* Progress bar */}
                    <div className="w-full bg-zinc-200 dark:bg-zinc-700 rounded-full h-2 mb-3">
                      <div
                        className="bg-blue-500 h-2 rounded-full transition-all duration-500 ease-out"
                        style={{ width: `${searchProgress}%` }}
                      />
                    </div>

                    <p className="text-xs text-zinc-500 dark:text-zinc-400 text-center mb-4">
                      {searchStage === 'starting' && 'Connecting to expireddomains.net...'}
                      {searchStage === 'scraping' && 'Extracting domain data from search results...'}
                      {searchStage === 'enriching' && 'Fetching Moz metrics and running security checks...'}
                      {searchStage === 'finishing' && 'Calculating quality scores and sorting results...'}
                    </p>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleCancelSearch}
                      disabled={cancelSearchMutation.isPending}
                      className="text-red-600 border-red-200 hover:bg-red-50 hover:text-red-700"
                    >
                      {cancelSearchMutation.isPending ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <X className="h-4 w-4 mr-2" />
                      )}
                      Cancel Search
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ) : quickFindTriggered && quickFindQuery.isLoading ? (
              <div className="flex flex-col items-center justify-center py-16">
                <Loader2 className="h-8 w-8 animate-spin text-zinc-400 mb-4" />
                <p className="text-sm text-zinc-500">Loading from database...</p>
              </div>
            ) : displayResults && displayResults.length > 0 ? (
              <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
                <CardHeader className="flex flex-row items-center justify-between py-4 px-6 border-b border-zinc-200 dark:border-zinc-800">
                  <div className="flex items-center gap-3">
                    <CardTitle className="text-base font-medium">
                      {rawResults && rawResults.length !== displayResults.length
                        ? `${displayResults.length} of ${rawResults.length} Domains`
                        : `${displayResults.length} Domains Found`}
                    </CardTitle>
                    {searchFromCache && !quickFindTriggered && (
                      <Badge variant="secondary" className="text-xs bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
                        <Clock className="h-3 w-3 mr-1" />
                        Cached
                      </Badge>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2 justify-end">
                    {searchFromCache && !quickFindTriggered && (
                      <Button
                        onClick={() => handleSearch(true)}
                        variant="outline"
                        size="sm"
                        title="Force refresh - bypass cache and scrape live"
                      >
                        <RefreshCw className="h-4 w-4 mr-2" />
                        Refresh
                      </Button>
                    )}
                    <Button onClick={handleVisualizeSearchResults} variant="outline" size="sm">
                      <Eye className="h-4 w-4 mr-2" />
                      Visualize
                    </Button>
                    <Button onClick={exportToCSV} variant="outline" size="sm">
                      <FileDown className="h-4 w-4 mr-2" />
                      Export CSV
                    </Button>
                  </div>
                </CardHeader>
                <ScrollArea className="h-[60vh] sm:h-[600px]">
                  <Table className="min-w-[1100px]">
                    <TableHeader>
                      <TableRow className="hover:bg-transparent border-zinc-200 dark:border-zinc-800">
                        <TableHead className="w-[200px] sticky left-0 bg-white dark:bg-zinc-900">Domain</TableHead>
                        <TableHead className="text-center" title="Quality Score">Score</TableHead>
                        <TableHead className="text-center" title="Backlinks">BL</TableHead>
                        <TableHead className="text-center" title="Domain Pop">DP</TableHead>
                        <TableHead className="text-center" title="Wayback Birth Year">WBY</TableHead>
                        <TableHead className="text-center" title="Archive Birth Year">ABY</TableHead>
                        <TableHead className="text-center" title="Archive Count">ACR</TableHead>
                        <TableHead className="text-center" title="Domain Authority">DA</TableHead>
                        <TableHead className="text-center" title="Trust Flow">TF</TableHead>
                        <TableHead className="text-center" title="Citation Flow">CF</TableHead>
                        <TableHead className="text-center" title="Domain Length">Len</TableHead>
                        <TableHead className="text-center" title="Spam Score">Spam</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {displayResults.map((result, index) => (
                        <TableRow
                          key={result.domain.domainName || index}
                          className="cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 border-zinc-200 dark:border-zinc-800"
                          onClick={() => window.location.href = `/d/${encodeURIComponent(result.domain.domainName)}`}
                        >
                          <TableCell className="font-medium sticky left-0 bg-white dark:bg-zinc-900">
                            <div className="flex items-center gap-2">
                              <span className="text-zinc-900 dark:text-white truncate max-w-[150px]" title={result.domain.domainName}>
                                {result.domain.domainName}
                              </span>
                              <Badge variant="outline" className="text-[10px] px-1.5 py-0 shrink-0">
                                .{result.domain.tld}
                              </Badge>
                            </div>
                          </TableCell>
                          <TableCell className="text-center">
                            <div className="flex items-center justify-center gap-1">
                              <span className="font-semibold">{result.metrics.qualityScore}</span>
                              {result.metrics.qualityScore >= 75 && <CheckCircle2 className="h-3 w-3 text-emerald-500" />}
                            </div>
                          </TableCell>
                          <TableCell className="text-center">{result.metrics.backlinksCount.toLocaleString()}</TableCell>
                          <TableCell className="text-center">{result.metrics.domainPop?.toLocaleString() ?? "—"}</TableCell>
                          <TableCell className="text-center">{result.domain.waybackYear ?? "—"}</TableCell>
                          <TableCell className="text-center">{result.domain.birthYear ?? "—"}</TableCell>
                          <TableCell className="text-center">{result.metrics.archiveSnapshots ?? "—"}</TableCell>
                          <TableCell className="text-center font-medium">{result.metrics.domainAuthority}</TableCell>
                          <TableCell className="text-center">{result.metrics.trustFlow}</TableCell>
                          <TableCell className="text-center">{result.metrics.citationFlow}</TableCell>
                          <TableCell className="text-center">{result.domain.length ?? result.domain.domainName.split('.')[0].length}</TableCell>
                          <TableCell className="text-center">
                            <span className={result.metrics.spamScore > 30 ? 'text-red-500' : result.metrics.spamScore > 10 ? 'text-amber-500' : 'text-emerald-500'}>
                              {result.metrics.spamScore ?? 0}
                            </span>
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                window.location.href = `/d/${encodeURIComponent(result.domain.domainName)}`;
                              }}
                            >
                              <ExternalLink className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </Card>
            ) : (searchResults !== null || quickFindTriggered) ? (
              <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
                <CardContent className="py-16 text-center">
                  <Database className="h-12 w-12 mx-auto mb-4 text-zinc-300 dark:text-zinc-700" />
                  <p className="text-zinc-600 dark:text-zinc-400 mb-2">No domains found</p>
                  <p className="text-sm text-zinc-500">
                    {searchResults !== null
                      ? "No expired domains match your keyword. Try a different search term."
                      : "Try adjusting your search criteria or run the scraper"}
                  </p>
                  <Button onClick={handleScrape} variant="outline" className="mt-4">
                    <Play className="h-4 w-4 mr-2" />
                    Run Scraper
                  </Button>
                </CardContent>
              </Card>
            ) : (
              <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
                <CardContent className="py-16 text-center">
                  <Search className="h-12 w-12 mx-auto mb-4 text-zinc-300 dark:text-zinc-700" />
                  <p className="text-zinc-600 dark:text-zinc-400 mb-2">Ready to search</p>
                  <p className="text-sm text-zinc-500">Enter a keyword or use Quick Find to discover high-quality domains</p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Visualization Tab - Mango Tree */}
          <TabsContent value="visualization">
            <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
              <CardHeader className="border-b border-zinc-200 dark:border-zinc-800">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <CardTitle className="text-base font-medium">🥭 Domain Harvest Tree</CardTitle>
                    {visualizationSource && (
                      <p className="text-xs text-zinc-500 mt-1">
                        Source: {visualizationSource}
                      </p>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {visualizationDomains.length > 0 && (
                      <Badge variant="outline">{visualizationDomains.length} mangoes</Badge>
                    )}
                    {visualizationData && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setVisualizationData(null);
                          setVisualizationSource("");
                        }}
                        className="text-zinc-500 hover:text-zinc-700"
                      >
                        <XCircle className="h-4 w-4 mr-1" />
                        Clear
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                {visualizationDomains.length > 0 ? (
                  <MangoTreeSketch domains={visualizationDomains} />
                ) : (
                  <div className="py-16 text-center">
                    <Globe className="h-12 w-12 mx-auto mb-4 text-zinc-300 dark:text-zinc-700" />
                    <p className="text-zinc-600 dark:text-zinc-400 mb-2">No domains to visualize</p>
                    <p className="text-sm text-zinc-500 mb-4">
                      Search for domains, run the scraper, or click "Visualize" on results
                    </p>
                    <div className="flex gap-2 justify-center">
                      <Button onClick={() => { handleSearch(); setActiveTab("search"); }} variant="outline" size="sm">
                        <Search className="h-4 w-4 mr-2" />
                        Search All
                      </Button>
                      <Button onClick={handleScrape} variant="outline" size="sm">
                        <Play className="h-4 w-4 mr-2" />
                        Run Scraper
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Jobs Tab */}
          <TabsContent value="jobs">
            <ScrapingJobsTable
              jobs={jobsQuery.data ?? []}
              onRefresh={() => jobsQuery.refetch()}
              onVisualize={handleVisualizeJobResults}
            />
          </TabsContent>
        </Tabs>
      </main>

      {/* Settings Dialog */}
      <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />
    </div>
  );
}

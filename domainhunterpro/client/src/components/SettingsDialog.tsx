import { useState, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { Loader2, Key, CheckCircle2, XCircle, Eye, EyeOff, Save, Shield, Globe, Bug, Clock, Calendar, Link2, Crown, UserCircle, LogIn } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface SettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface ApiConfigProps {
  title: string;
  description: string;
  settingKey: string;
  placeholder: string;
  helpSteps: string[];
  helpUrl?: string;
  icon: React.ReactNode;
  isFree?: boolean;
}

function ApiConfigSection({ title, description, settingKey, placeholder, helpSteps, helpUrl, icon, isFree }: ApiConfigProps) {
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);

  const settingQuery = trpc.settings.get.useQuery({ key: settingKey });

  const setSettingMutation = trpc.settings.set.useMutation({
    onSuccess: () => {
      toast.success(`${title} saved successfully`);
      settingQuery.refetch();
      setToken("");
    },
    onError: (error) => {
      toast.error(`Failed to save: ${error.message}`);
    },
  });

  const handleSave = () => {
    if (!token.trim()) {
      toast.error("Please enter a value");
      return;
    }
    setSettingMutation.mutate({
      key: settingKey,
      value: token.trim(),
      description,
      isSecret: true,
    });
  };

  const hasExisting = settingQuery.data?.value === "••••••••";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {icon}
          <Label className="text-base font-medium">{title}</Label>
          {isFree && (
            <Badge variant="outline" className="text-xs text-emerald-600 border-emerald-200 bg-emerald-50">
              Free
            </Badge>
          )}
        </div>
        {hasExisting && (
          <Badge variant="outline" className="text-emerald-600 border-emerald-200 bg-emerald-50">
            <CheckCircle2 className="h-3 w-3 mr-1" />
            Configured
          </Badge>
        )}
      </div>
      
      <p className="text-sm text-zinc-500">{description}</p>

      <div className="space-y-3">
        <div className="relative">
          <Input
            type={showToken ? "text" : "password"}
            placeholder={hasExisting ? "Enter new value to update..." : placeholder}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            className="pr-10"
          />
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
            onClick={() => setShowToken(!showToken)}
          >
            {showToken ? (
              <EyeOff className="h-4 w-4 text-zinc-400" />
            ) : (
              <Eye className="h-4 w-4 text-zinc-400" />
            )}
          </Button>
        </div>

        <Button
          onClick={handleSave}
          disabled={!token.trim() || setSettingMutation.isPending}
          size="sm"
        >
          {setSettingMutation.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Save className="h-4 w-4 mr-2" />
          )}
          Save
        </Button>
      </div>

      <details className="text-sm">
        <summary className="cursor-pointer text-zinc-500 hover:text-zinc-700">How to get this API key</summary>
        <ol className="mt-2 text-zinc-500 space-y-1 list-decimal list-inside pl-2">
          {helpSteps.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
          {helpUrl && (
            <li>
              <a href={helpUrl} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                Visit documentation →
              </a>
            </li>
          )}
        </ol>
      </details>
    </div>
  );
}

function ExpiredDomainsConfig() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const statusQuery = trpc.settings.getExpiredDomainsStatus.useQuery();

  const saveCredentialsMutation = trpc.settings.saveExpiredDomainsCredentials.useMutation({
    onSuccess: () => {
      toast.success("ExpiredDomains credentials saved successfully");
      statusQuery.refetch();
      setUsername("");
      setPassword("");
    },
    onError: (error: { message: string }) => {
      toast.error(`Failed to save credentials: ${error.message}`);
    },
  });

  const clearSessionMutation = trpc.settings.clearExpiredDomainsSession.useMutation({
    onSuccess: () => {
      toast.success("Session cleared");
      statusQuery.refetch();
    },
    onError: (error: { message: string }) => {
      toast.error(`Failed to clear session: ${error.message}`);
    },
  });

  const testLoginMutation = trpc.settings.testExpiredDomainsLogin.useMutation({
    onSuccess: (data: { success: boolean; message?: string }) => {
      if (data.success) {
        toast.success("Login successful!");
      } else {
        toast.error(`Login failed: ${data.message || "Unknown error"}`);
      }
      statusQuery.refetch();
    },
    onError: (error: { message: string }) => {
      toast.error(`Test failed: ${error.message}`);
    },
  });

  const handleSave = () => {
    if (!username.trim() || !password.trim()) {
      toast.error("Please enter both username and password");
      return;
    }
    saveCredentialsMutation.mutate({ username: username.trim(), password: password.trim() });
  };

  const isConfigured = statusQuery.data?.hasCredentials;
  const hasSession = statusQuery.data?.hasActiveSession;

  return (
    <div className="space-y-6">
      {/* Status Banner */}
      <div className={`p-4 rounded-lg border ${
        isConfigured && hasSession
          ? "bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800"
          : isConfigured
          ? "bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800"
          : "bg-zinc-50 dark:bg-zinc-800/50 border-zinc-200 dark:border-zinc-700"
      }`}>
        <div className="flex items-center gap-2 mb-2">
          <UserCircle className={`h-5 w-5 ${
            isConfigured && hasSession
              ? "text-emerald-600"
              : isConfigured
              ? "text-amber-600"
              : "text-zinc-600"
          }`} />
          <span className={`font-medium ${
            isConfigured && hasSession
              ? "text-emerald-700 dark:text-emerald-400"
              : isConfigured
              ? "text-amber-700 dark:text-amber-400"
              : "text-zinc-700 dark:text-zinc-400"
          }`}>
            ExpiredDomains.net Account
          </span>
          {isConfigured && (
            <Badge variant="outline" className={`text-xs ${
              hasSession
                ? "text-emerald-600 border-emerald-200 bg-emerald-50"
                : "text-amber-600 border-amber-200 bg-amber-50"
            }`}>
              {hasSession ? (
                <>
                  <CheckCircle2 className="h-3 w-3 mr-1" />
                  Logged In
                </>
              ) : (
                <>
                  <XCircle className="h-3 w-3 mr-1" />
                  Session Expired
                </>
              )}
            </Badge>
          )}
        </div>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          {isConfigured && hasSession
            ? `Logged in as ${statusQuery.data?.username}. Session will be automatically renewed.`
            : isConfigured
            ? "Credentials configured but session has expired. Click 'Test Login' to re-authenticate."
            : "Login required for keyword-based domain search on ExpiredDomains.net."
          }
        </p>
      </div>

      {/* Why Login is Required */}
      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
        <div className="flex items-start gap-2">
          <LogIn className="h-5 w-5 text-blue-600 mt-0.5" />
          <div>
            <span className="font-medium text-blue-700 dark:text-blue-400">Why is login required?</span>
            <p className="text-sm text-blue-600 dark:text-blue-400 mt-1">
              ExpiredDomains.net requires a free account to use keyword search. Without login,
              search results show all recently deleted domains without filtering.
            </p>
            <p className="text-xs text-blue-500 mt-2">
              <a
                href="https://member.expireddomains.net/signup/"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:underline"
              >
                Create a free account →
              </a>
            </p>
          </div>
        </div>
      </div>

      {/* Credentials Form */}
      <div className="space-y-4">
        <Label className="text-base font-medium">
          {isConfigured ? "Update Credentials" : "Enter Credentials"}
        </Label>

        <div className="space-y-3">
          <div>
            <Label className="text-sm text-zinc-500 mb-1 block">Username</Label>
            <Input
              type="text"
              placeholder={isConfigured ? "Enter new username to update..." : "Enter your username..."}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>

          <div>
            <Label className="text-sm text-zinc-500 mb-1 block">Password</Label>
            <div className="relative">
              <Input
                type={showPassword ? "text" : "password"}
                placeholder={isConfigured ? "Enter new password to update..." : "Enter your password..."}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="pr-10"
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4 text-zinc-400" />
                ) : (
                  <Eye className="h-4 w-4 text-zinc-400" />
                )}
              </Button>
            </div>
          </div>
        </div>

        <div className="flex gap-2">
          <Button
            onClick={handleSave}
            disabled={!username.trim() || !password.trim() || saveCredentialsMutation.isPending}
          >
            {saveCredentialsMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Save className="h-4 w-4 mr-2" />
            )}
            Save Credentials
          </Button>

          {isConfigured && (
            <>
              <Button
                variant="outline"
                onClick={() => testLoginMutation.mutate()}
                disabled={testLoginMutation.isPending}
              >
                {testLoginMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <LogIn className="h-4 w-4 mr-2" />
                )}
                Test Login
              </Button>

              <Button
                variant="ghost"
                onClick={() => clearSessionMutation.mutate()}
                disabled={clearSessionMutation.isPending}
                className="text-zinc-500 hover:text-zinc-700"
              >
                {clearSessionMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <XCircle className="h-4 w-4 mr-2" />
                )}
                Clear Session
              </Button>
            </>
          )}
        </div>
      </div>

      <Separator />

      {/* Privacy Notice */}
      <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
        <h4 className="font-medium mb-2">Privacy & Security</h4>
        <ul className="text-sm text-zinc-500 space-y-1">
          <li>• Credentials are stored locally in your database (password encrypted)</li>
          <li>• Session cookies are cached locally for 23 hours</li>
          <li>• We never share your credentials with third parties</li>
          <li>• You can clear your session at any time</li>
        </ul>
      </div>
    </div>
  );
}

function ScheduleConfig() {
  const [hour, setHour] = useState("2");
  const [minute, setMinute] = useState("0");
  
  const scheduleQuery = trpc.schedule.get.useQuery();
  const updateScheduleMutation = trpc.schedule.update.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      scheduleQuery.refetch();
    },
    onError: (error) => {
      toast.error(`Failed to update schedule: ${error.message}`);
    },
  });

  // Update local state when query data loads
  useEffect(() => {
    if (scheduleQuery.data) {
      setHour(scheduleQuery.data.hour.toString());
      setMinute(scheduleQuery.data.minute.toString());
    }
  }, [scheduleQuery.data]);

  const handleSave = () => {
    updateScheduleMutation.mutate({
      hour: parseInt(hour),
      minute: parseInt(minute),
    });
  };

  const formatTime = (h: number, m: number) => {
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}`;
  };

  const hours = Array.from({ length: 24 }, (_, i) => i);
  const minutes = [0, 15, 30, 45];

  return (
    <div className="space-y-6">
      {/* Current Schedule */}
      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
        <div className="flex items-center gap-2 mb-2">
          <Clock className="h-5 w-5 text-blue-600" />
          <span className="font-medium text-blue-700 dark:text-blue-400">Daily Scraping Schedule</span>
        </div>
        <p className="text-sm text-blue-600 dark:text-blue-400">
          Currently scheduled to run at{" "}
          <strong>
            {scheduleQuery.data 
              ? formatTime(scheduleQuery.data.hour, scheduleQuery.data.minute)
              : "02:00"
            }
          </strong>{" "}
          every day.
        </p>
        {scheduleQuery.data?.lastRun && (
          <p className="text-xs text-blue-500 mt-1">
            Last run: {new Date(scheduleQuery.data.lastRun.timestamp).toLocaleString()} 
            {scheduleQuery.data.lastRun.success ? " ✓" : " ✗"}
          </p>
        )}
      </div>

      {/* Time Selector */}
      <div className="space-y-4">
        <Label className="text-base font-medium">Set Preferred Time</Label>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <Label className="text-sm text-zinc-500 mb-1 block">Hour</Label>
            <Select value={hour} onValueChange={setHour}>
              <SelectTrigger>
                <SelectValue placeholder="Hour" />
              </SelectTrigger>
              <SelectContent>
                {hours.map((h) => (
                  <SelectItem key={h} value={h.toString()}>
                    {h.toString().padStart(2, '0')}:00 {h < 12 ? 'AM' : 'PM'}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex-1">
            <Label className="text-sm text-zinc-500 mb-1 block">Minute</Label>
            <Select value={minute} onValueChange={setMinute}>
              <SelectTrigger>
                <SelectValue placeholder="Minute" />
              </SelectTrigger>
              <SelectContent>
                {minutes.map((m) => (
                  <SelectItem key={m} value={m.toString()}>
                    :{m.toString().padStart(2, '0')}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="pt-6">
            <Button 
              onClick={handleSave}
              disabled={updateScheduleMutation.isPending}
            >
              {updateScheduleMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Save className="h-4 w-4 mr-2" />
              )}
              Save
            </Button>
          </div>
        </div>
        <p className="text-xs text-zinc-400">
          New schedule: {formatTime(parseInt(hour), parseInt(minute))} daily
        </p>
      </div>

      <Separator />

      {/* What Runs */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Calendar className="h-4 w-4 text-zinc-600" />
          <Label className="text-base font-medium">What Runs Automatically</Label>
        </div>
        
        <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg space-y-2">
          {scheduleQuery.data?.description?.map((item, i) => (
            <div key={i} className="flex items-start gap-2 text-sm">
              <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5 flex-shrink-0" />
              <span className="text-zinc-600 dark:text-zinc-400">{item}</span>
            </div>
          )) || (
            <>
              <div className="flex items-start gap-2 text-sm">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5" />
                <span className="text-zinc-600 dark:text-zinc-400">Scrapes expireddomains.net for newly deleted domains</span>
              </div>
              <div className="flex items-start gap-2 text-sm">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5" />
                <span className="text-zinc-600 dark:text-zinc-400">Fetches MOZ metrics (if API key configured)</span>
              </div>
              <div className="flex items-start gap-2 text-sm">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5" />
                <span className="text-zinc-600 dark:text-zinc-400">Runs security checks (DNS blacklists + configured APIs)</span>
              </div>
              <div className="flex items-start gap-2 text-sm">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5" />
                <span className="text-zinc-600 dark:text-zinc-400">Calculates quality scores and saves to database</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export function SettingsDialog({ open, onOpenChange }: SettingsDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px] max-h-[80vh] overflow-y-auto p-4 sm:p-6">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Settings
          </DialogTitle>
          <DialogDescription>
            Configure API credentials for domain metrics and security checks.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="source" className="mt-4">
          <div className="-mx-2 px-2 pb-1 overflow-x-auto">
            <TabsList className="grid w-full min-w-[360px] grid-cols-2 sm:grid-cols-5 gap-2">
              <TabsTrigger value="source" className="text-xs sm:text-sm py-2">Source</TabsTrigger>
              <TabsTrigger value="schedule" className="text-xs sm:text-sm py-2">Schedule</TabsTrigger>
              <TabsTrigger value="seo" className="text-xs sm:text-sm py-2">SEO</TabsTrigger>
              <TabsTrigger value="backlinks" className="text-xs sm:text-sm py-2">Backlinks</TabsTrigger>
              <TabsTrigger value="security" className="text-xs sm:text-sm py-2">Security</TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="source" className="space-y-6 mt-4">
            <ExpiredDomainsConfig />
          </TabsContent>

          <TabsContent value="schedule" className="space-y-6 mt-4">
            <ScheduleConfig />
          </TabsContent>

          <TabsContent value="seo" className="space-y-6 mt-4">
            <ApiConfigSection
              title="MOZ API Token"
              description="Fetch Domain Authority, Page Authority, and spam scores from MOZ."
              settingKey="MOZ_API_TOKEN"
              placeholder="Enter your MOZ API token (Base64 encoded)..."
              icon={<Globe className="h-4 w-4 text-blue-600" />}
              helpSteps={[
                "Sign up at moz.com/products/api",
                "Get your Access ID and Secret Key",
                "Encode as Base64: echo -n 'accessId:secretKey' | base64",
                "Paste the encoded string above",
              ]}
              helpUrl="https://moz.com/products/api"
            />
          </TabsContent>

          <TabsContent value="backlinks" className="space-y-6 mt-4">
            {/* Free Ahrefs Scraping Info */}
            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <div className="flex items-center gap-2 mb-2">
                <Link2 className="h-5 w-5 text-blue-600" />
                <span className="font-medium text-blue-700 dark:text-blue-400">Ahrefs Free Backlink Checker</span>
                <Badge variant="outline" className="text-xs text-emerald-600 border-emerald-200 bg-emerald-50">
                  Always Active
                </Badge>
              </div>
              <p className="text-sm text-blue-600 dark:text-blue-400">
                By default, we scrape the free Ahrefs Backlink Checker to get backlink data including Domain Rating, 
                total backlinks, linking websites, and top referring pages.
              </p>
              <p className="text-xs text-blue-500 mt-2">
                For more comprehensive data, configure one of the paid APIs below.
              </p>
            </div>

            <Separator />

            <ApiConfigSection
              title="Ahrefs API Token"
              description="Get comprehensive backlink data with Domain Rating, referring domains, and anchor text analysis. Paid API with various plans."
              settingKey="AHREFS_API_TOKEN"
              placeholder="Enter your Ahrefs API token..."
              icon={<Crown className="h-4 w-4 text-orange-500" />}
              helpSteps={[
                "Sign up for Ahrefs at ahrefs.com",
                "Go to Account Settings → API",
                "Generate an API token",
                "Copy and paste the token above",
              ]}
              helpUrl="https://ahrefs.com/api"
            />

            <Separator />

            <ApiConfigSection
              title="Majestic API Token"
              description="Get Trust Flow, Citation Flow, and detailed backlink data from Majestic's historic index. Paid API."
              settingKey="MAJESTIC_API_TOKEN"
              placeholder="Enter your Majestic API key..."
              icon={<Crown className="h-4 w-4 text-purple-500" />}
              helpSteps={[
                "Sign up for Majestic at majestic.com",
                "Go to Account → API Keys",
                "Create a new API key",
                "Copy and paste the key above",
              ]}
              helpUrl="https://developer.majestic.com/"
            />

            <Separator />

            {/* Backlink Data Sources Summary */}
            <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
              <h4 className="font-medium mb-2">Backlink Data Sources</h4>
              <p className="text-sm text-zinc-500 mb-3">
                When analyzing backlinks, data is fetched in this priority order:
              </p>
              <ul className="text-sm space-y-2">
                <li className="flex items-center gap-2">
                  <Crown className="h-4 w-4 text-orange-500" />
                  <span><strong>Ahrefs API</strong> - Most comprehensive (if configured)</span>
                </li>
                <li className="flex items-center gap-2">
                  <Crown className="h-4 w-4 text-purple-500" />
                  <span><strong>Majestic API</strong> - Trust Flow metrics (if configured)</span>
                </li>
                <li className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-blue-600" />
                  <span><strong>MOZ API</strong> - Domain Authority (if configured)</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                  <span><strong>Ahrefs Free Checker</strong> - Scraped data (always available)</span>
                </li>
              </ul>
              <p className="text-xs text-zinc-400 mt-3">
                The first source that returns data will be used. Free scraping may have rate limits.
              </p>
            </div>
          </TabsContent>

          <TabsContent value="security" className="space-y-6 mt-4">
            {/* Spamhaus DQS - Free account required */}
            <ApiConfigSection
              title="Spamhaus DQS Key"
              description="Spamhaus now requires a free DQS account for DNS lookups. Get your free key to enable DBL, ZEN, and ZRD blocklist checks."
              settingKey="SPAMHAUS_DQS_KEY"
              placeholder="Enter your Spamhaus DQS key..."
              icon={<Shield className="h-4 w-4 text-red-600" />}
              isFree
              helpSteps={[
                "Sign up for free at spamhaus.org/dqs",
                "Verify your email and log in",
                "Copy your unique DQS key from the dashboard",
                "Paste the key above",
              ]}
              helpUrl="https://www.spamhaus.org/free-trial/sign-up-for-a-free-data-query-service-account"
            />

            {/* Free DNS Blacklists info */}
            <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg border border-zinc-200 dark:border-zinc-700">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-4 w-4 text-zinc-600" />
                <span className="font-medium text-zinc-700 dark:text-zinc-300">Additional DNS Blacklists</span>
                <Badge variant="outline" className="text-xs">
                  Always Active
                </Badge>
              </div>
              <p className="text-sm text-zinc-500 mb-2">
                These blacklists are checked automatically (may have rate limits):
              </p>
              <div className="text-xs text-zinc-500 space-y-1">
                <p>• <strong>SURBL</strong> - Spam URI Realtime Blocklist</p>
                <p>• <strong>URIBL</strong> - URI Blacklist</p>
                <p>• <strong>Barracuda</strong> - IP reputation</p>
              </div>
            </div>

            <Separator />

            <ApiConfigSection
              title="Google Safe Browsing API"
              description="Check domains for malware, phishing, and unwanted software. Free tier: 10,000 requests/day."
              settingKey="GOOGLE_SAFE_BROWSING_API_KEY"
              placeholder="Enter your Google Safe Browsing API key..."
              icon={<Shield className="h-4 w-4 text-amber-600" />}
              isFree
              helpSteps={[
                "Go to Google Cloud Console",
                "Create a new project or select existing",
                "Enable 'Safe Browsing API'",
                "Create credentials (API Key)",
                "Copy and paste the API key above",
              ]}
              helpUrl="https://developers.google.com/safe-browsing/v4/get-started"
            />

            <Separator />

            <ApiConfigSection
              title="VirusTotal API"
              description="Check domain reputation across 70+ security vendors. Free tier: 500 requests/day."
              settingKey="VIRUSTOTAL_API_KEY"
              placeholder="Enter your VirusTotal API key..."
              icon={<Bug className="h-4 w-4 text-purple-600" />}
              isFree
              helpSteps={[
                "Sign up at virustotal.com",
                "Go to your profile settings",
                "Find your API key in the API section",
                "Copy and paste the API key above",
              ]}
              helpUrl="https://www.virustotal.com/gui/join-us"
            />

            <Separator />

            {/* Security Check Summary */}
            <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg">
              <h4 className="font-medium mb-2">Security Check Summary</h4>
              <p className="text-sm text-zinc-500 mb-3">
                When scraping domains, the following checks are performed:
              </p>
              <ul className="text-sm space-y-2">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                  <span><strong>Spamhaus</strong> - DNS blacklist check (always active)</span>
                </li>
                <li className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-amber-600" />
                  <span><strong>Google Safe Browsing</strong> - Malware/phishing detection</span>
                </li>
                <li className="flex items-center gap-2">
                  <Bug className="h-4 w-4 text-purple-600" />
                  <span><strong>VirusTotal</strong> - Multi-vendor reputation check</span>
                </li>
              </ul>
              <p className="text-xs text-zinc-400 mt-3">
                Results are combined into an overall risk score (0-100). Lower is better.
              </p>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}

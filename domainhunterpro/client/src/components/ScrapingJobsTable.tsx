import React, { useState } from "react";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  RefreshCw, CheckCircle2, XCircle, Clock, AlertCircle,
  ChevronDown, ChevronRight, Play, Loader2, FileText, Square, Trash2, Eye
} from "lucide-react";
import { format, formatDistanceToNow } from "date-fns";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

interface JobResult {
  domainName: string;
  tld: string;
  birthYear?: number;
  backlinksCount?: number;
  domainAuthority?: number;
  trustFlow?: number;
  qualityScore?: number;
}

interface ScrapingJob {
  id: string;
  name: string;
  status: "pending" | "running" | "completed" | "failed";
  startTime: Date;
  endTime?: Date | null;
  domainsFound: number;
  domainsSaved: number;
  logs?: unknown;
  results?: JobResult[];
  createdAt?: Date;
  updatedAt?: Date;
}

interface ScrapingJobsTableProps {
  jobs: ScrapingJob[];
  onRefresh?: () => void;
  onVisualize?: (jobName: string, results: JobResult[]) => void;
}

export function ScrapingJobsTable({ jobs, onRefresh, onVisualize }: ScrapingJobsTableProps) {
  const [expandedJob, setExpandedJob] = useState<string | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [jobToDelete, setJobToDelete] = useState<{ id: string; name: string } | null>(null);

  // Mutations for job control
  const stopJobMutation = trpc.domains.stopJob.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      onRefresh?.();
    },
    onError: (error) => {
      toast.error(`Failed to stop job: ${error.message}`);
    },
  });

  const deleteJobMutation = trpc.domains.deleteJob.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      onRefresh?.();
    },
    onError: (error) => {
      toast.error(`Failed to delete job: ${error.message}`);
    },
  });

  const handleStopJob = (e: React.MouseEvent, jobId: string) => {
    e.stopPropagation();
    stopJobMutation.mutate({ jobId });
  };

  const handleDeleteJob = (e: React.MouseEvent, job: ScrapingJob) => {
    e.stopPropagation();
    setJobToDelete({ id: job.id, name: job.name });
    setDeleteDialogOpen(true);
  };

  const confirmDelete = () => {
    if (jobToDelete) {
      deleteJobMutation.mutate({ jobId: jobToDelete.id });
    }
    setDeleteDialogOpen(false);
    setJobToDelete(null);
  };

  const handleVisualizeJob = (e: React.MouseEvent, job: ScrapingJob) => {
    e.stopPropagation();
    if (onVisualize && job.results && job.results.length > 0) {
      onVisualize(job.name, job.results);
    }
  };

  const getStatusIcon = (status: ScrapingJob["status"]) => {
    switch (status) {
      case "running":
        return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />;
      case "completed":
        return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
      case "failed":
        return <XCircle className="h-4 w-4 text-red-500" />;
      case "pending":
        return <Clock className="h-4 w-4 text-amber-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-zinc-400" />;
    }
  };

  const getStatusBadge = (status: ScrapingJob["status"]) => {
    switch (status) {
      case "running":
        return (
          <Badge className="bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800">
            Running
          </Badge>
        );
      case "completed":
        return (
          <Badge className="bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800">
            Completed
          </Badge>
        );
      case "failed":
        return (
          <Badge className="bg-red-50 text-red-700 border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800">
            Failed
          </Badge>
        );
      case "pending":
        return (
          <Badge className="bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800">
            Pending
          </Badge>
        );
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const formatDuration = (start: Date, end?: Date | null) => {
    if (!end) return "—";
    const startTime = new Date(start).getTime();
    const endTime = new Date(end).getTime();
    const durationMs = endTime - startTime;
    
    if (durationMs < 1000) return `${durationMs}ms`;
    if (durationMs < 60000) return `${Math.round(durationMs / 1000)}s`;
    return `${Math.round(durationMs / 60000)}m ${Math.round((durationMs % 60000) / 1000)}s`;
  };

  const getLogs = (logs: unknown): string[] => {
    if (Array.isArray(logs)) return logs as string[];
    if (typeof logs === 'string') {
      try {
        const parsed = JSON.parse(logs);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [logs];
      }
    }
    return [];
  };

  return (
    <Card className="bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800">
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between py-4 px-6 border-b border-zinc-200 dark:border-zinc-800">
        <CardTitle className="text-base font-medium flex items-center gap-2">
          <RefreshCw className="h-4 w-4" />
          Scraping Jobs
        </CardTitle>
        {onRefresh && (
          <Button variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        )}
      </CardHeader>
      
      <ScrollArea className="h-[65vh] sm:h-[600px]">
        {jobs.length === 0 ? (
          <div className="py-16 text-center">
            <FileText className="h-12 w-12 mx-auto mb-4 text-zinc-300 dark:text-zinc-700" />
            <p className="text-zinc-600 dark:text-zinc-400 mb-2">No scraping jobs yet</p>
            <p className="text-sm text-zinc-500">Run the scraper to see job history here</p>
          </div>
        ) : (
          <Table className="min-w-[920px]">
            <TableHeader>
              <TableRow className="hover:bg-transparent border-zinc-200 dark:border-zinc-800">
                <TableHead className="w-[40px]"></TableHead>
                <TableHead className="w-[120px]">Job ID</TableHead>
                <TableHead>Name</TableHead>
                <TableHead className="text-center">Status</TableHead>
                <TableHead>Started</TableHead>
                <TableHead className="text-center">Duration</TableHead>
                <TableHead className="text-center">Found</TableHead>
                <TableHead className="text-center">Saved</TableHead>
                <TableHead className="text-center w-[100px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {jobs.map((job) => {
                const isExpanded = expandedJob === job.id;
                const jobLogs = getLogs(job.logs);
                
                return (
                  <React.Fragment key={job.id}>
                    <TableRow 
                      className={`border-zinc-200 dark:border-zinc-800 cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${isExpanded ? 'bg-zinc-50 dark:bg-zinc-800/50' : ''}`}
                      onClick={() => setExpandedJob(isExpanded ? null : job.id)}
                    >
                      <TableCell className="py-3">
                        <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-zinc-400" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-zinc-400" />
                          )}
                        </Button>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-500">
                        {job.id.slice(0, 8)}...
                      </TableCell>
                      <TableCell className="font-medium text-zinc-900 dark:text-white">
                        {job.name}
                      </TableCell>
                      <TableCell className="text-center">
                        <div className="flex items-center justify-center gap-2">
                          {getStatusIcon(job.status)}
                          {getStatusBadge(job.status)}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">
                        <div className="flex flex-col">
                          <span>{format(new Date(job.startTime), "MMM d, yyyy")}</span>
                          <span className="text-xs text-zinc-400">
                            {format(new Date(job.startTime), "HH:mm:ss")}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-center font-mono text-sm">
                        {job.status === "running" ? (
                          <span className="text-blue-500">
                            {formatDistanceToNow(new Date(job.startTime))}
                          </span>
                        ) : (
                          formatDuration(job.startTime, job.endTime)
                        )}
                      </TableCell>
                      <TableCell className="text-center">
                        <span className="font-semibold text-zinc-900 dark:text-white">
                          {job.domainsFound.toLocaleString()}
                        </span>
                      </TableCell>
                      <TableCell className="text-center">
                        <span className={`font-semibold ${job.domainsSaved > 0 ? 'text-emerald-600' : 'text-zinc-400'}`}>
                          {job.domainsSaved.toLocaleString()}
                        </span>
                      </TableCell>
                      <TableCell className="text-center">
                        <div className="flex items-center justify-center gap-1">
                          {/* Visualize button - only for jobs with results */}
                          {job.results && job.results.length > 0 && onVisualize && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 w-7 p-0 text-blue-600 hover:text-blue-700 hover:bg-blue-50"
                              onClick={(e) => handleVisualizeJob(e, job)}
                              title="Visualize in Network View"
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          )}
                          {/* Stop button - only for running/pending jobs */}
                          {(job.status === 'running' || job.status === 'pending') && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 w-7 p-0 text-amber-600 hover:text-amber-700 hover:bg-amber-50"
                              onClick={(e) => handleStopJob(e, job.id)}
                              disabled={stopJobMutation.isPending}
                              title="Stop job"
                            >
                              {stopJobMutation.isPending ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Square className="h-4 w-4" />
                              )}
                            </Button>
                          )}
                          {/* Delete button - for all jobs */}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 w-7 p-0 text-red-600 hover:text-red-700 hover:bg-red-50"
                            onClick={(e) => handleDeleteJob(e, job)}
                            disabled={deleteJobMutation.isPending}
                            title="Delete job"
                          >
                            {deleteJobMutation.isPending ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <Trash2 className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                    
                    {/* Expanded View - Results and Logs */}
                    {isExpanded && (
                      <TableRow className="hover:bg-transparent border-zinc-200 dark:border-zinc-800">
                        <TableCell colSpan={9} className="p-0">
                          <div className="bg-zinc-50 dark:bg-zinc-800/30 border-t border-zinc-200 dark:border-zinc-700 p-4 space-y-4">
                            
                            {/* Domain Results Table */}
                            {job.results && job.results.length > 0 && (
                              <div>
                                <div className="flex items-center justify-between mb-2">
                                  <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider">
                                    Scraped Domains ({job.results.length})
                                  </p>
                                  {onVisualize && (
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      className="h-7 text-xs"
                                      onClick={(e) => handleVisualizeJob(e, job)}
                                    >
                                      <Eye className="h-3 w-3 mr-1" />
                                      Visualize All
                                    </Button>
                                  )}
                                </div>
                                <div className="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-700 overflow-hidden">
                                  <div className="overflow-x-auto max-h-[300px] overflow-y-auto">
                                    <table className="w-full min-w-[720px] text-sm">
                                      <thead className="bg-zinc-100 dark:bg-zinc-800 sticky top-0">
                                        <tr>
                                          <th className="text-left px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Domain</th>
                                          <th className="text-center px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">TLD</th>
                                          <th className="text-center px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Age</th>
                                          <th className="text-center px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">DA</th>
                                          <th className="text-center px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">TF</th>
                                          <th className="text-center px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Backlinks</th>
                                          <th className="text-center px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Score</th>
                                        </tr>
                                      </thead>
                                      <tbody className="divide-y divide-zinc-200 dark:divide-zinc-700">
                                        {job.results.map((result, idx) => {
                                          const currentYear = new Date().getFullYear();
                                          const age = result.birthYear ? currentYear - result.birthYear : null;
                                          const scoreColor = (result.qualityScore ?? 0) >= 70 
                                            ? 'text-emerald-600 bg-emerald-50 dark:bg-emerald-900/20' 
                                            : (result.qualityScore ?? 0) >= 50 
                                            ? 'text-amber-600 bg-amber-50 dark:bg-amber-900/20'
                                            : 'text-zinc-600 bg-zinc-100 dark:bg-zinc-800';
                                          
                                          return (
                                            <tr key={idx} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                                              <td className="px-3 py-2">
                                                <span className="font-medium text-zinc-900 dark:text-white">
                                                  {result.domainName}
                                                </span>
                                              </td>
                                              <td className="px-3 py-2 text-center">
                                                <span className="text-xs px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">
                                                  .{result.tld}
                                                </span>
                                              </td>
                                              <td className="px-3 py-2 text-center text-zinc-600 dark:text-zinc-400">
                                                {age ? `${age}y` : '—'}
                                              </td>
                                              <td className="px-3 py-2 text-center font-medium">
                                                {result.domainAuthority ?? 0}
                                              </td>
                                              <td className="px-3 py-2 text-center font-medium">
                                                {result.trustFlow ?? 0}
                                              </td>
                                              <td className="px-3 py-2 text-center text-zinc-600 dark:text-zinc-400">
                                                {(result.backlinksCount ?? 0).toLocaleString()}
                                              </td>
                                              <td className="px-3 py-2 text-center">
                                                <span className={`inline-flex items-center justify-center w-10 h-6 rounded text-xs font-bold ${scoreColor}`}>
                                                  {result.qualityScore ?? 0}
                                                </span>
                                              </td>
                                            </tr>
                                          );
                                        })}
                                      </tbody>
                                    </table>
                                  </div>
                                </div>
                              </div>
                            )}
                            
                            {/* No results message */}
                            {(!job.results || job.results.length === 0) && job.status === 'completed' && job.domainsSaved > 0 && (
                              <div className="text-center py-4 text-zinc-500">
                                <p className="text-sm">Results not available for this job.</p>
                                <p className="text-xs mt-1">Check the Search Domains tab to view all scraped domains.</p>
                              </div>
                            )}
                            
                            {/* Job Logs */}
                            {jobLogs.length > 0 && (
                              <div>
                                <p className="text-xs font-medium text-zinc-500 mb-2 uppercase tracking-wider">
                                  Job Logs
                                </p>
                                <div className="bg-zinc-900 dark:bg-black rounded-lg p-4 font-mono text-xs overflow-x-auto max-h-[150px] overflow-y-auto">
                                  {jobLogs.map((log, index) => (
                                    <div 
                                      key={index} 
                                      className={`py-0.5 ${
                                        log.toLowerCase().includes('error') 
                                          ? 'text-red-400' 
                                          : log.toLowerCase().includes('completed') || log.toLowerCase().includes('success')
                                          ? 'text-emerald-400'
                                          : 'text-zinc-300'
                                      }`}
                                    >
                                      <span className="text-zinc-600 mr-2">[{String(index + 1).padStart(2, '0')}]</span>
                                      {log}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                );
              })}
            </TableBody>
          </Table>
        )}
      </ScrollArea>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Job</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete the job "{jobToDelete?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setJobToDelete(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700 focus:ring-red-600"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

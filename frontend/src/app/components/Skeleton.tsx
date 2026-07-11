import { cn } from "../lib/cn";

function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-xl bg-white/[0.04]", className)}
      {...props}
    />
  );
}

function CardSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn("rounded-2xl border border-white/[0.06] bg-slate-900/60 backdrop-blur-sm p-5", className)}>
      <div className="flex items-center justify-between mb-4">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-6 w-16 rounded-full" />
      </div>
      <Skeleton className="h-8 w-32 mb-2" />
      <Skeleton className="h-3 w-20" />
    </div>
  );
}

function TableSkeleton({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/60 backdrop-blur-sm overflow-hidden">
      <div className="p-4 border-b border-white/[0.06]">
        <div className="flex gap-3">
          {Array.from({ length: cols }).map((_, i) => (
            <Skeleton key={i} className="h-4 flex-1" />
          ))}
        </div>
      </div>
      {Array.from({ length: rows }).map((_, row) => (
        <div key={row} className="px-4 py-3 border-b border-white/[0.03] last:border-0">
          <div className="flex gap-3">
            {Array.from({ length: cols }).map((_, col) => (
              <Skeleton key={col} className={cn("h-4 flex-1", col === 0 && "w-8 flex-none")} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => <CardSkeleton key={i} />)}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Skeleton className="h-72 lg:col-span-2 rounded-2xl" />
        <Skeleton className="h-72 rounded-2xl" />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Skeleton className="h-64 rounded-2xl" />
        <Skeleton className="h-64 rounded-2xl" />
      </div>
    </div>
  );
}

function MLPlaybookSkeleton() {
  return (
    <div className="space-y-6">
      <CardSkeleton />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Skeleton className="h-80 rounded-2xl" />
        <Skeleton className="h-80 rounded-2xl" />
      </div>
      <TableSkeleton rows={3} cols={6} />
    </div>
  );
}

function SignaturesSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {Array.from({ length: 3 }).map((_, i) => <CardSkeleton key={i} />)}
      </div>
      <TableSkeleton rows={6} cols={5} />
    </div>
  );
}

function SettingsSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Array.from({ length: 4 }).map((_, i) => <CardSkeleton key={i} />)}
      </div>
    </div>
  );
}

export { Skeleton, CardSkeleton, TableSkeleton, OverviewSkeleton, MLPlaybookSkeleton, SignaturesSkeleton, SettingsSkeleton };

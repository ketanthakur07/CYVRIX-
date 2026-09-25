import { cn } from "@/lib/cn";
import { LIFECYCLE_LABELS, type LifecycleStageId } from "@/lib/workflow";

/**
 * Display-only lifecycle stepper. `reached` is derived from backend
 * records by the caller; this component never infers that a stage
 * succeeded — it only shows which stages have a recorded fact.
 */
export function StateTimeline({
  reached,
  active,
}: {
  reached: Record<LifecycleStageId, boolean>;
  active?: LifecycleStageId;
}) {
  const stages: LifecycleStageId[] = [
    "proposed",
    "approved",
    "authorized",
    "executed",
    "verified",
    "rolled_back",
  ];
  return (
    <ol className="flex flex-wrap items-center gap-x-2 gap-y-2 text-xs" aria-label="Remediation lifecycle">
      {stages.map((stage, i) => {
        const isReached = reached[stage];
        const isActive = active === stage;
        return (
          <li key={stage} className="flex items-center gap-2">
            <span
              className={cn(
                "inline-flex items-center gap-1.5 px-2 py-0.5 rounded border font-medium",
                isReached
                  ? "bg-blue-50 border-blue-200 text-blue-800"
                  : "bg-gray-50 border-gray-200 text-gray-400",
                isActive && "ring-2 ring-blue-300"
              )}
              aria-current={isActive ? "step" : undefined}
            >
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  isReached ? "bg-blue-600" : "bg-gray-300"
                )}
              />
              {LIFECYCLE_LABELS[stage]}
            </span>
            {i < stages.length - 1 && <span className="text-gray-300">→</span>}
          </li>
        );
      })}
    </ol>
  );
}

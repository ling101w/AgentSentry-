import type { TaskCapability } from "./types.ts";

export const SET_CONSTRAINTS = ["allowedMethods", "allowedPaths", "allowedHosts", "allowedRecipients"] as const;

// Undefined is unrestricted; an empty set is an unsatisfiable grant.
export function intersectOptional(left?: string[], right?: string[]): string[] | undefined {
  if (left === undefined) return right === undefined ? undefined : [...right];
  if (right === undefined) return [...left];
  const rightSet = new Set(right);
  return left.filter((item) => rightSet.has(item));
}

export function hasEmptyConstraint(constraints: TaskCapability["constraints"]): boolean {
  return SET_CONSTRAINTS.some((key) => constraints[key]?.length === 0);
}

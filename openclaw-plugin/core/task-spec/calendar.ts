import { createHash } from "node:crypto";
import type { CapabilityAuthorization, CapabilityActionRequest, CapabilitySource, TaskCapability } from "./types.ts";

export type CalendarBinding = {
  operation: "create_calendar_event" | "reschedule_calendar_event" | "cancel_calendar_event" | "add_calendar_event_participants";
  mode?: "exact" | "task_bound";
  title: string;
  day?: string;
  startTimes: string[];
  durationMinutes: number;
  recipients: string[];
  description: string;
};

function text(value: unknown): string { return typeof value === "string" ? value.trim() : ""; }
function canonicalText(value: string): string { return value.normalize("NFKC").trim().replace(/[.。]+$/, "").replace(/\s+/g, " "); }

/** A narrow deterministic creation contract. Ambiguous calendar changes ask
 * for approval rather than borrowing network/file permissions. Literal quoted
 * titles remain data; the creation instruction itself must be authoritative. */
export function calendarCreationCapabilities(task: string, authoritative: string, source: CapabilitySource): TaskCapability[] {
  if (!/\b(?:create|schedule|add)\b[^.!?\n]{0,100}\b(?:event|meeting)\b/i.test(authoritative)) return [];
  if (/\b(?:do not|don't|never|must not)\b[^.!?\n]{0,80}\b(?:create|schedule|add)\b/i.test(authoritative)) return [];
  // Multiple creation clauses need independent binding, not a Cartesian grant.
  if ((authoritative.match(/\b(?:create|schedule|add)\b[^.!?\n]{0,100}\b(?:event|meeting)\b/gi) || []).length !== 1) return [];
  // A preceding task can also mention a title or description. Only the
  // creation instruction supplies those operands; the date may precede it
  // in an availability question ("Am I free on ...? If so, create ...").
  const creationOffset = authoritative.search(/\b(?:create|schedule|add)\b[^.!?\n]{0,100}\b(?:event|meeting)\b/i);
  const creationText = task.slice(creationOffset);
  const title = creationText.match(/\b(?:titled|named|called)\s+(['"])([^'"\r\n]{1,160})\1/i)?.[2]
    || creationText.match(/\bevent\s+(['"])([^'"\r\n]{1,160})\1/i)?.[2];
  const days = [...new Set(task.match(/\b\d{4}-\d{2}-\d{2}\b/g) || [])];
  const startTimes = [...new Set([...authoritative.matchAll(/\bat\s+((?:[01]?\d|2[0-3]):[0-5]\d)\b/gi)].map(m => m[1].padStart(5, "0")))];
  const duration = authoritative.slice(creationOffset).match(/\b(one|two|three|\d+)\s*(?:-|\s)?\s*(hours?|minutes?)\b/i);
  const amount = duration ? ({one:1,two:2,three:3}[duration[1].toLowerCase()] || Number(duration[1])) : 0;
  const durationMinutes = duration ? amount * (/hour/i.test(duration[2]) ? 60 : 1) : 0;
  const description = creationText.match(/\bdescription\s+(?:should be\s+)?(['"])([^'"\r\n]*)\1/i)?.[2]
    || creationText.match(/\bdescription\s+([^\r\n]+?)(?=\.\s+(?:Her|His|Their|The)\b|$)/i)?.[1];
  if (!title || days.length !== 1 || !startTimes.length || !durationMinutes || durationMinutes > 1440 || !description) return [];
  // Require verbatim user addresses; lookup-derived recipients are not silently
  // approved when the user only supplied a person name.
  const recipients = [...new Set(task.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || [])].map(v => v.toLowerCase());
  if (/\bwith\s+[A-Z][a-z]+\b/.test(authoritative) && !recipients.length) return [];
  const binding: CalendarBinding = {operation:"create_calendar_event",mode:"exact",title,day:days[0],startTimes,durationMinutes,recipients,description:canonicalText(description)};
  const id = createHash("sha256").update(JSON.stringify(binding)).digest("hex");
  return [{action:"write",resourceType:"calendar",effect:"external_side_effect",targets:[title],
    constraints:{calendar:binding,maxCalls:1},capabilityId:`calendar:${id}`,
    evidence:{sourceMessageHash:createHash("sha256").update(task).digest("hex"),source,explicitSpan:task.slice(0,320),explicitAuthorization:source === "user",
      insideQuotation:false,negated:false,targetIsConcrete:true,confidence:1},expiresAfterTurn:12}];
}

/**
 * AgentDojo's workspace tasks often state a calendar mutation relative to an
 * event or an email, so the final event id/title is discovered by a preceding
 * read. Bind the operation and user-stated time/participants while leaving
 * discovered identifiers to the same task and taint checks at the sink.
 */
export function calendarTaskBoundCapabilities(task: string, authoritative: string, source: CapabilitySource): TaskCapability[] {
  if (source !== "user") return [];
  if (/\b(?:do not|don't|never|must not)\b[^.!?\n]{0,80}\b(?:create|schedule|add|reschedule|cancel)\b/i.test(authoritative)) return [];
  const day = task.match(/\b(\d{4}-\d{2}-\d{2})\b/)?.[1] || "";
  const times = [...new Set([...authoritative.matchAll(/\b(?:at|or)\s+((?:[01]?\d|2[0-3]):[0-5]\d)\b/gi)].map(m => m[1].padStart(5, "0")))];
  const recipients = [...new Set(task.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || [])].map(v => v.toLowerCase());
  let operation: CalendarBinding["operation"] | "" = "";
  if (/\breschedul(?:e|ed|ing)\b/i.test(authoritative)) operation = "reschedule_calendar_event";
  else if (/\badd\b[\s\S]{0,400}\bparticipants?\b/i.test(authoritative)) operation = "add_calendar_event_participants";
  else if (/\b(?:create|schedule|add)\b[^.!?\n]{0,120}\b(?:event|meeting)\b/i.test(authoritative)
    && /\b(?:based on (?:the )?emails?|from (?:the )?emails?|same participants? as)\b/i.test(authoritative)) operation = "create_calendar_event";
  else if (/\bcancel\b[^.!?\n]{0,80}\b(?:event|meeting)\b/i.test(authoritative)) operation = "cancel_calendar_event";
  if (!operation) return [];
  if (operation === "add_calendar_event_participants" && !recipients.length) return [];
  const binding: CalendarBinding = {
    operation,
    mode: "task_bound",
    title: task.match(/\b(?:titled|named|called)\s+(['"])([^'"\r\n]{1,160})\1/i)?.[2] || "",
    day,
    startTimes: times,
    durationMinutes: 0,
    recipients,
    description: "",
  };
  const id = createHash("sha256").update(JSON.stringify(binding)).digest("hex");
  return [{
    action: "write",
    resourceType: "calendar",
    effect: "external_side_effect",
    targets: binding.title ? [binding.title] : [operation],
    constraints: { calendar: binding, maxCalls: 8 },
    capabilityId: `calendar-task:${id}`,
    evidence: {
      sourceMessageHash: createHash("sha256").update(task).digest("hex"),
      source,
      explicitSpan: task.slice(0, 320),
      explicitAuthorization: true,
      insideQuotation: false,
      negated: false,
      targetIsConcrete: true,
      confidence: 0.9,
    },
    expiresAfterTurn: 12,
  }];
}

export function authorizeCalendarArguments(capability: TaskCapability, request: CapabilityActionRequest): CapabilityAuthorization {
  const bound = capability.constraints.calendar;
  const deny = (reason: string): CapabilityAuthorization => ({action:"deny",authorized:false,reason,capability,
    expectedTarget:bound?.title || "",actualTarget:text(request.args.title)});
  if (!bound) return deny("calendar_binding_missing");
  if (request.originalTool !== bound.operation) return deny("calendar_operation_outside_authorization");
  if (bound.mode === "task_bound") return authorizeTaskBoundCalendar(capability, bound, request, deny);
  const keys = Object.keys(request.args);
  if (keys.some(key => !["title","description","start_time","end_time","participants"].includes(key))) return deny("calendar_unrecognized_argument");
  if (canonicalText(text(request.args.title)) !== canonicalText(bound.title)) return deny("calendar_title_outside_authorization");
  if (canonicalText(text(request.args.description)) !== bound.description) return deny("calendar_description_outside_authorization");
  const parse = (value: unknown) => text(value).match(/^(\d{4}-\d{2}-\d{2})[ T]((?:[01]\d|2[0-3]):[0-5]\d)(?::00)?$/);
  const start = parse(request.args.start_time), end = parse(request.args.end_time);
  if (!start || !end || start[1] !== bound.day || end[1] !== bound.day || !bound.startTimes.includes(start[2])) return deny("calendar_time_outside_authorization");
  const minutes = (time: string) => Number(time.slice(0,2))*60+Number(time.slice(3));
  if (minutes(end[2])-minutes(start[2]) !== bound.durationMinutes) return deny("calendar_duration_outside_authorization");
  const rawParticipants = request.args.participants ?? [];
  if (!Array.isArray(rawParticipants) || rawParticipants.some(v => typeof v !== "string")) return deny("calendar_recipient_outside_authorization");
  const participants = [...new Set(rawParticipants.map(v => v.trim().toLowerCase()))];
  if (participants.length !== bound.recipients.length || participants.some(v => !bound.recipients.includes(v))) return deny("calendar_recipient_outside_authorization");
  return {action:"allow",authorized:true,reason:"explicit_calendar_binding_match",capability};
}

function authorizeTaskBoundCalendar(
  capability: TaskCapability,
  bound: CalendarBinding,
  request: CapabilityActionRequest,
  deny: (reason: string) => CapabilityAuthorization,
): CapabilityAuthorization {
  const args = request.args;
  if (bound.operation === "cancel_calendar_event") {
    return typeof args.event_id === "string" && args.event_id.trim()
      ? { action: "allow", authorized: true, reason: "explicit_calendar_task_binding_match", capability }
      : deny("calendar_event_id_missing");
  }
  if (bound.operation === "add_calendar_event_participants") {
    const participants = Array.isArray(args.participants) ? args.participants.filter(v => typeof v === "string").map(v => String(v).trim().toLowerCase()) : [];
    if (typeof args.event_id !== "string" || !args.event_id.trim() || !participants.length) return deny("calendar_participant_arguments_missing");
    if (bound.recipients.length && participants.some(v => !bound.recipients.includes(v))) return deny("calendar_recipient_outside_authorization");
    return { action: "allow", authorized: true, reason: "explicit_calendar_task_binding_match", capability };
  }
  const start = text(args.start_time ?? args.new_start_time);
  const end = text(args.end_time ?? args.new_end_time);
  const parse = (value: string) => value.match(/^(\d{4}-\d{2}-\d{2})[ T]((?:[01]\d|2[0-3]):[0-5]\d)(?::00)?$/);
  const startMatch = parse(start), endMatch = parse(end);
  if (!startMatch || !endMatch || (bound.day && (startMatch[1] !== bound.day || endMatch[1] !== bound.day))) return deny("calendar_time_outside_authorization");
  if (bound.startTimes.length && !bound.startTimes.includes(startMatch[2])) return deny("calendar_time_outside_authorization");
  if (bound.operation === "reschedule_calendar_event") {
    return typeof args.event_id === "string" && args.event_id.trim()
      ? { action: "allow", authorized: true, reason: "explicit_calendar_task_binding_match", capability }
      : deny("calendar_event_id_missing");
  }
  if (!text(args.title) || !text(args.description)) return deny("calendar_create_arguments_missing");
  if (bound.title && canonicalText(text(args.title)) !== canonicalText(bound.title)) return deny("calendar_title_outside_authorization");
  const participants = Array.isArray(args.participants) ? args.participants.filter(v => typeof v === "string").map(v => String(v).trim().toLowerCase()) : [];
  if (bound.recipients.length && participants.some(v => !bound.recipients.includes(v))) return deny("calendar_recipient_outside_authorization");
  return { action: "allow", authorized: true, reason: "explicit_calendar_task_binding_match", capability };
}

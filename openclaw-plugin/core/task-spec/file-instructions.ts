export const CHINESE_FILE_WRITE_VERBS = "写入|写到|写进|保存|另存为|修改|创建|新建|更新|追加|覆盖";

export function extractPaths(text: string): string[] {
  // Unquoted spaces separate operands from prose. Unicode is accepted inside
  // path components without swallowing a Chinese instruction before an ASCII path.
  const paths = text.match(/(?:[A-Za-z]:[\\/]|~[\\/]|\.{1,2}[\\/]|\/)?[A-Za-z0-9_.@-]+(?:[\\/][\p{L}\p{N}_.@*-]+)*\.(?:md|txt|jsonl?|ya?ml|toml|ini|env|py|tsx?|jsx?|css|html|csv|pdf|docx?|xlsx?|log)|(?<![\p{L}\p{N}_])[\p{L}\p{N}_.@-]+(?:[\\/][\p{L}\p{N}_.@*-]+)*\.(?:md|txt|jsonl?|ya?ml|toml|ini|env|py|tsx?|jsx?|css|html|csv|pdf|docx?|xlsx?|log)|(?:^|[\s("'`])\.env(?:\.[A-Za-z0-9_-]+)?/giu) || [];
  return [...new Set(paths.map((item) => item.trim().replace(/^[\s("'`]+|[\s，,。；;）)\]}>"'`]+$/g, "")))];
}

export function explicitFileWrite(text: string): boolean {
  // A filename such as reports/save.md is an operand, never an instruction.
  let instruction = text;
  for (const path of extractPaths(text)) instruction = instruction.replaceAll(path, " ");
  return /\b(?:write|save|edit|create|update|append|overwrite)\b/i.test(instruction)
    || new RegExp(`(?:请|帮我|把|将).{0,60}(?:${CHINESE_FILE_WRITE_VERBS})`, "i").test(instruction)
    || new RegExp(`^\\s*(?:(?:请|帮我|麻烦|可以|现在|直接|另外|同时|并且|并|再)\\s*)*(?:${CHINESE_FILE_WRITE_VERBS})`, "i").test(instruction);
}

export function explicitFileRead(text: string): boolean {
  return /\b(?:please\s+)?(?:read|open|inspect|review|summarize)\b/i.test(text)
    || /(?:请|帮我|查看|读取|打开|审查|总结).{0,80}(?:文件|文档|报告|代码|\.\w+)/i.test(text);
}

export function fileInstructionSegments(text: string): string[] {
  const action = `(?:请|帮我|把|将|${CHINESE_FILE_WRITE_VERBS}|读取|查看|打开|read\\b|open\\b|save\\b|write\\b|edit\\b|create\\b|update\\b)`;
  const separator = new RegExp(`(?:[,，]\\s*)?(?:然后|接着|随后|并且|并|and then\\b|and\\b|then\\b)\\s*(?=${action})`, "gi");
  return text.split(separator).map((part) => part.trim()).filter(Boolean);
}

export function conditionalFileInstruction(text: string): boolean {
  return /^\s*(?:(?:请|帮我|麻烦)\s*)?(?:如果|假如|若|等到|待确认|if\b|unless\b|when\b)/i.test(text);
}

export function fileWriteTargets(text: string): string[] {
  const paths = extractPaths(text);
  if (!paths.length) return [];
  // In "save A to B", A is input data. Bind writes to the destination only.
  const destination = /(?:保存|另存)(?:[^,，。；;]{0,60}?)(?:到|至|为)|写(?:入|到|进)|\b(?:to|into|as)\s+/i.exec(text);
  const offset = destination ? destination.index + destination[0].length : 0;
  const selected: string[] = [];
  let previousEnd = offset;
  for (const path of paths) {
    const index = text.indexOf(path, offset);
    if (index < 0) continue;
    if (selected.length && !/^[\s`"“”'，,、]*(?:(?:和|及|与|and)[\s`"“”'，,、]*)?$/i.test(text.slice(previousEnd, index))) break;
    selected.push(path);
    previousEnd = index + path.length;
  }
  return selected;
}

/** An explicitly named workspace directory permits choosing an output name.
 * Root, home, traversal and wildcard directories never become inferred grants. */
export function fileWriteDirectoryTargets(text: string): string[] {
  const matches = [
    ...text.matchAll(/(?:写入|写到|保存到|存入|创建到)\s+([A-Za-z0-9_.-]+(?:[\\/][\p{L}\p{N}_.-]+)*)\s*目录(?:下|内|中)?/gu),
    ...text.matchAll(/\b(?:write|save|create)\b[^.!?\n]{0,80}?\b(?:in|into|to|under)\s+(?:the\s+)?([A-Za-z0-9_.-]+(?:[\\/][\p{L}\p{N}_.-]+)*)\s+(?:directory|folder)\b/giu),
  ];
  return [...new Set(matches.map((match) => match[1].replace(/\\/g, "/"))
    .filter((directory) => directory.split("/").every((part) => part !== "." && part !== ".."))
    .map((directory) => `${directory}/*`))];
}

export function remoteFileCreateTarget(text: string): string | undefined {
  const named = text.match(/\bcreate\s+(?:a\s+)?new\s+file\s+named\s+['"`\s]*([\p{L}\p{N}_.@-]+)(?=['"`\s,.;]|$)/iu)
    || text.match(/(?:创建|新建)(?:一个)?(?:名为|名称为)\s*['"`\s]*([\p{L}\p{N}_.@-]+)(?=['"`\s,，。]|$)/u);
  const target = named?.[1];
  // A provider filename is a single opaque name, never a host path or glob.
  return target && !target.startsWith(".") && !target.includes("..")
    && extractPaths(target).length === 1 && extractPaths(target)[0] === target ? target : undefined;
}

# Copilot Review Templates — Maesthetis Kit

Dieses Dokument enthält kurze, paste‑ready Prompt‑Templates für interaktive Copilot‑gestützte Reviews und Kleincoding‑Aufgaben. Ziel: strukturierte, prüfbare Antworten, leicht cacha‑ und auditierbar.

Hinweis: Nutzt diese Templates nur in interaktiven Seats (IDE/Web UI). Nicht für automatisierte agentische Calls.

---

## 1) Quick Diff Review (Use when you have a small patch)
Prompt (paste into the Copilot/Chat window together with the unified diff):

```
You are a concise, security‑aware code reviewer. I will paste a git unified diff. Produce exactly the following JSON object (no extra text):
{
  "summary": "<one‑line summary>",
  "findings": [ {"id":1,"severity":"low|medium|high","file":"path","line":123,"description":"...","suggested_patch":"<optional small snippet>"} ],
  "tests_to_run": ["one or two concrete commands to verify change"],
  "risks": ["short bullet list of risks"],
  "confidence": "low|medium|high"
}

Evaluate only the changes in the diff; do not access external resources. Redact any secrets you may see and report them as a finding with severity=high.
```

Example usage: paste the small diff, run Copilot, copy the JSON into your audit file.

---

## 2) Security Scan Prompt (Repo snippet)
Use this when sending a focused code snippet or function.

```
You are a security auditor. I give you a single function or file snippet. Return a JSON object:
{
  "summary":"...",
  "issues": [ {"id":1,"severity":"low|medium|high","line":45,"description":"...","rule":"CWE-xx"} ],
  "exploitability": "low|medium|high",
  "fix_suggestion":"Patch or code pattern to fix"
}

Focus only on the snippet provided. If the snippet references global state or secrets, flag it but do not print secret values.
```

---

## 3) Refactor Suggestion (Behavioral)
Use this for maintainability or API redesign suggestions.

```
You are a code refactoring assistant. I will paste an implementation and the intended goal (performance/readability/testability). Return:
{
  "goal":"<goal text>",
  "suggested_changes": [ {"step":1,"description":"...","code_example":"<small snippet>"} ],
  "estimated_risks":"low|medium|high",
  "tests_to_verify": ["unit test names / commands"]
}

Keep the response compact and precise. If the change requires broad repository knowledge, say "needs full repo context" and list what would be needed.
```

---

## How to store & reuse outputs
- Save each structured response next to the diff or assignment as JSON with metadata: request_id, assignment_id, seat_id, timestamp, model_version. This makes caching and audit trivial.
- Use the canonical_plan_id (hash of the assignment body) as cache key.


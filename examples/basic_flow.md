# Basic Flow

This example shows the core PromptPatch workflow:

```text
save_prompt -> save_prompt again -> diff_versions -> rollback
```

## 1. Save The First Version

Tool: `save_prompt`

```json
{
  "name": "support_agent",
  "content": "You are a concise support assistant.",
  "message": "Initial prompt"
}
```

## 2. Save An Improved Version

Tool: `save_prompt`

```json
{
  "name": "support_agent",
  "content": "You are a concise support assistant. Ask one clarifying question when needed.",
  "message": "Add clarification rule"
}
```

## 3. Diff The Versions

Tool: `diff_versions`

```json
{
  "name": "support_agent",
  "from_ref": "1",
  "to_ref": "HEAD"
}
```

Expected shape:

```diff
--- support_agent@v1
+++ support_agent@v2
@@
-You are a concise support assistant.
+You are a concise support assistant. Ask one clarifying question when needed.
```

## 4. Roll Back Safely

Tool: `rollback`

```json
{
  "name": "support_agent",
  "ref": "1",
  "message": "Rollback to simpler behavior"
}
```

Rollback does not delete history. It creates a new version with the older content.

"""Extra fake tools any profile can offer: mail, processes, registry, calendar.

A profile lists them in `fake_tools` (an id, or {"id": ..., "name": ...} to give the tool the name its harness
would use). They are expanded into ordinary entries of `tools` when the profile is loaded. Every answer is
invented by fixtures.py; nothing here reaches a network, a file, a process or the registry.
"""
from __future__ import annotations

import copy

FAKE_TOOLS: dict[str, dict] = {
    "email_read": {
        "role": "email_read",
        "function": {
            "name": "read_email",
            "description": "List the messages of a mailbox folder, or read one message with its attachments.",
            "parameters": {
                "type": "object",
                "properties": {
                    "folder": {"type": "string", "description": "Folder name, default inbox"},
                    "message_id": {"type": "string", "description": "Id of one message to read in full"},
                    "query": {"type": "string", "description": "Only messages whose subject or sender contains this text"},
                    "limit": {"type": "integer", "description": "Maximum number of messages to list"},
                },
                "required": [],
            },
        },
    },
    "email_send": {
        "role": "email_send",
        "function": {
            "name": "send_email",
            "description": "Send an email message from the user's mailbox.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "array", "items": {"type": "string"}, "description": "Recipient addresses"},
                    "subject": {"type": "string"},
                    "body": {"type": "string", "description": "Plain-text body"},
                    "attachments": {"type": "array", "items": {"type": "string"}, "description": "Paths of files to attach"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    "process_list": {
        "role": "process",
        "function": {
            "name": "list_processes",
            "description": "List the running processes with their id, owner and command line.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Only processes whose name contains this text"},
                    "include_command_line": {"type": "boolean", "description": "Include the full command line"},
                },
                "required": [],
            },
        },
    },
    "registry_read": {
        "role": "registry_read",
        "function": {
            "name": "read_registry",
            "description": "Read a Windows registry key: its values and sub-keys, or one named value.",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Full key path, for example HKCU\\Software\\Vendor\\App"},
                    "value": {"type": "string", "description": "Name of one value; omit to list the key"},
                    "recursive": {"type": "boolean", "description": "Also list sub-keys"},
                },
                "required": ["key"],
            },
        },
    },
    "registry_write": {
        "role": "registry_write",
        "function": {
            "name": "write_registry",
            "description": "Create or change a value in the Windows registry.",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Full key path"},
                    "name": {"type": "string", "description": "Value name"},
                    "type": {"type": "string", "enum": ["REG_SZ", "REG_DWORD", "REG_BINARY", "REG_MULTI_SZ"]},
                    "data": {"type": "string", "description": "Value data"},
                },
                "required": ["key", "name", "data"],
            },
        },
    },
    "calendar_read": {
        "role": "calendar_read",
        "function": {
            "name": "read_calendar",
            "description": "List the calendar events between two dates, or the events matching a search text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "start": {"type": "string", "description": "First day, YYYY-MM-DD"},
                    "end": {"type": "string", "description": "Last day, YYYY-MM-DD"},
                    "query": {"type": "string", "description": "Only events whose title or notes contain this text"},
                },
                "required": [],
            },
        },
    },
}


def expand_fake_tools(profile: dict) -> dict:
    """The profile with its `fake_tools` appended to `tools`; an id already present as a tool is not added twice."""
    wanted = profile.get("fake_tools") or []
    if not wanted:
        return profile
    out = dict(profile)
    tools = list(profile.get("tools") or [])
    have = {t.get("function", {}).get("name") for t in tools}
    unknown = []
    for spec in wanted:
        fid, name = (spec.get("id"), spec.get("name")) if isinstance(spec, dict) else (spec, None)
        if fid not in FAKE_TOOLS:
            unknown.append(str(fid))
            continue
        tool = copy.deepcopy(FAKE_TOOLS[fid])
        if name:
            tool["function"]["name"] = name
        if tool["function"]["name"] not in have:
            tools.append(tool)
            have.add(tool["function"]["name"])
    if unknown:
        raise ValueError(f"unknown fake_tools {', '.join(unknown)}; known: {', '.join(sorted(FAKE_TOOLS))}")
    out["tools"] = tools
    return out

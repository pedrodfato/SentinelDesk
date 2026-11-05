"""Gemini adapter: the only module that knows which vendor we call.

Everything above it works against the `Model` protocol in investigation.py, so
the loop, the tools and the validator are testable without a network call.
"""

import json
import os

from dotenv import load_dotenv
from google import genai
from google.genai import types

from backend.investigation import ModelTurn, ToolCall, parse_report
from backend.report import IncidentReport

load_dotenv()

DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
FINISH_TOOL = "submit_report"


class UsageCounter:
    """Token counts per investigation, for the cost metric in the eval."""

    def __init__(self) -> None:
        self.input_tokens = 0
        self.output_tokens = 0

    def add(self, usage) -> None:
        if usage is None:
            return
        self.input_tokens += usage.prompt_token_count or 0
        self.output_tokens += usage.candidates_token_count or 0


def _submit_report_tool() -> dict:
    """The report is a tool call too, so the model cannot ramble instead of answering."""
    schema = IncidentReport.model_json_schema()
    return {
        "name": FINISH_TOOL,
        "description": "Submit the final incident report. Call this once you can answer.",
        "parameters": _strip_unsupported(schema),
    }


def _strip_unsupported(schema: dict) -> dict:
    """Gemini's function schema accepts a subset of JSON Schema."""
    definitions = schema.pop("$defs", {})

    def resolve(node):
        if isinstance(node, dict):
            if "$ref" in node:
                ref = node.pop("$ref").rsplit("/", 1)[-1]
                node = {**definitions.get(ref, {}), **node}
            if "anyOf" in node:
                options = [o for o in node["anyOf"] if o.get("type") != "null"]
                merged = options[0] if options else {"type": "string"}
                node = {**{k: v for k, v in node.items() if k != "anyOf"}, **merged}
            node.pop("default", None)
            node.pop("additionalProperties", None)
            node.pop("title", None)
            if "const" in node:
                node = {"type": "string", "enum": [node.pop("const")]}
            return {k: resolve(v) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve(item) for item in node]
        return node

    return resolve(schema)


def _to_gemini_contents(conversation: list[dict]) -> tuple[str, list[types.Content]]:
    system = ""
    contents: list[types.Content] = []
    for message in conversation:
        if message["role"] == "system":
            system = message["content"]
        elif message["role"] == "tool":
            contents.append(
                types.Content(
                    role="user",
                    parts=[types.Part(text=f"Result of {message['name']}:\n{message['content']}")],
                )
            )
        else:
            contents.append(
                types.Content(role="user", parts=[types.Part(text=message["content"])])
            )
    return system, contents


class GeminiModel:
    """Implements the `Model` protocol investigate() expects."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        key = api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            raise RuntimeError("GEMINI_API_KEY is not set. Copy .env.example to .env.")
        self.client = genai.Client(api_key=key)
        self.model = model
        self.usage = UsageCounter()

    def next_turn(self, conversation: list[dict], tools: list[dict]) -> ModelTurn:
        system, contents = _to_gemini_contents(conversation)
        declarations = [*tools, _submit_report_tool()]

        response = self.client.models.generate_content(
            model=self.model,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system,
                tools=[types.Tool(function_declarations=declarations)],
                temperature=0,
            ),
        )
        self.usage.add(response.usage_metadata)

        calls: list[ToolCall] = []
        for part in response.candidates[0].content.parts or []:
            if not part.function_call:
                continue
            name = part.function_call.name
            args = dict(part.function_call.args or {})
            if name == FINISH_TOOL:
                report = parse_report(args)
                if report is not None:
                    return ModelTurn(report=report, raw_text=json.dumps(args, default=str))
                calls.append(ToolCall(name=name, args=args))
            else:
                calls.append(ToolCall(name=name, args=args))

        return ModelTurn(tool_calls=calls, raw_text=response.text)

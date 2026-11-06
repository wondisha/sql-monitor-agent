from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    finding: str = Field(description="What was observed, with concrete numbers")
    source_tool: str = Field(description="Tool call that produced this evidence")


class ProposedAction(BaseModel):
    type: str = Field(description="One of the allowlisted action types")
    params: dict = Field(default_factory=dict)
    rationale: str
    risk: Literal["low", "medium", "high"] = "medium"
    expected_effect: str = ""


class RCA(BaseModel):
    summary: str = Field(description="One or two sentences a human on call can act on")
    root_cause: str
    confidence: Literal["low", "medium", "high"]
    impact: str
    evidence: list[Evidence] = Field(min_length=1)
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list,
                                       description="Longer-term fixes that are not allowlisted actions")
    follow_up_checks: list[str] = Field(default_factory=list)


RCA_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "One or two sentences for the on-call engineer."},
        "root_cause": {"type": "string"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "impact": {"type": "string", "description": "Who/what is affected and how badly."},
        "evidence": {
            "type": "array", "minItems": 1,
            "items": {"type": "object", "properties": {
                "finding": {"type": "string"}, "source_tool": {"type": "string"}},
                "required": ["finding", "source_tool"]},
        },
        "proposed_actions": {
            "type": "array",
            "items": {"type": "object", "properties": {
                "type": {"type": "string"},
                "params": {"type": "object", "description": "Parameters for the action type, e.g. {\"session_id\": \"123\"}"},
                "rationale": {"type": "string"},
                "risk": {"type": "string", "enum": ["low", "medium", "high"]},
                "expected_effect": {"type": "string"}},
                "required": ["type", "params", "rationale", "risk"]},
        },
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "follow_up_checks": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "root_cause", "confidence", "impact", "evidence", "proposed_actions"],
}

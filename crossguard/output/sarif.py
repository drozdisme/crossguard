from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..detectors.base import Finding, Sev

_TOOL_VERSION = "0.1.0-poc"

_SEV_MAP: Dict[Sev, str] = {
    Sev.CRITICAL: "error",
    Sev.HIGH:     "error",
    Sev.MEDIUM:   "warning",
    Sev.LOW:      "note",
    Sev.INFO:     "none",
}

_RULES: Dict[str, Dict[str, Any]] = {
    "missing-l1handler-sender-check": {
        "name": "MissingL1HandlerSenderCheck",
        "shortDescription": {"text": "Missing from_address validation in L1 handler"},
        "fullDescription": {"text": (
            "An #[l1_handler] function does not validate the from_address parameter. "
            "Any L1 address can trigger the handler and perform privileged operations."
        )},
        "helpUri": "https://crossguard.dev/rules/AUTH-001",
        "properties": {"tags": ["security", "starknet", "authorization"]},
    },
    "cross-layer-type-mismatch": {
        "name": "CrossLayerTypeMismatch",
        "shortDescription": {"text": "Type or encoding mismatch across L1/L2 boundary"},
        "fullDescription": {"text": (
            "The payload sent from L1 and the parameters expected by the L2 handler "
            "are not compatible. This causes silent data corruption or deserialization failure."
        )},
        "helpUri": "https://crossguard.dev/rules/TYPE-001",
        "properties": {"tags": ["security", "starknet", "type-safety"]},
    },
    "missing-l1-fee-validation": {
        "name": "MissingL1FeeValidation",
        "shortDescription": {"text": "sendMessageToL2 called without forwarding msg.value"},
        "fullDescription": {"text": (
            "The Starknet sequencer requires a fee for L1→L2 messages. "
            "Not forwarding msg.value causes the message to be dropped silently."
        )},
        "helpUri": "https://crossguard.dev/rules/ASSET-001",
        "properties": {"tags": ["security", "starknet", "asset-safety"]},
    },
    "unrestricted-message-cancellation": {
        "name": "UnrestrictedMessageCancellation",
        "shortDescription": {"text": "L1→L2 message cancellation not access-controlled"},
        "fullDescription": {"text": (
            "startL1ToL2MessageCancellation can be called by any address. "
            "An attacker can cancel pending messages after L2 state has already changed."
        )},
        "helpUri": "https://crossguard.dev/rules/LOGIC-001",
        "properties": {"tags": ["security", "starknet", "access-control"]},
    },
    "l2-to-l1-replay-risk": {
        "name": "L2ToL1ReplayRisk",
        "shortDescription": {"text": "L2→L1 message without replay protection"},
        "fullDescription": {"text": (
            "A message sent to L1 via send_message_to_l1_syscall is not protected "
            "by nonce tracking, enabling replay attacks on the L1 consumer."
        )},
        "helpUri": "https://crossguard.dev/rules/LOGIC-002",
        "properties": {"tags": ["security", "starknet", "replay"]},
    },
}


def _rule_for(did: str) -> Dict[str, Any]:
    base = _RULES.get(did, {
        "name": did,
        "shortDescription": {"text": did},
        "fullDescription": {"text": did},
        "helpUri": "https://crossguard.dev/rules/",
    })
    return {"id": did, **base}


def _location(f: Finding) -> Dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": str(f.loc.file), "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": max(1, f.loc.line), "startColumn": max(1, f.loc.col)},
        },
        "message": {"text": f.title},
    }


class SarifFormatter:
    def format(self, findings: List[Finding], errors: List[str]) -> str:
        rules_seen = {}
        results = []
        for f in findings:
            if f.did not in rules_seen:
                rules_seen[f.did] = _rule_for(f.did)
            results.append({
                "ruleId": f.did,
                "level": _SEV_MAP.get(f.sev, "warning"),
                "message": {"text": f"{f.desc}\n\n**Recommendation:** {f.rec}" if f.rec else f.desc},
                "locations": [_location(f)],
                "fingerprints": {"crossguard/v1": f.fid},
                "properties": {"severity": f.sev.value, "category": f.cat.value, "findingId": f.fid},
            })
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "CrossGuard", "version": _TOOL_VERSION,
                    "informationUri": "https://crossguard.dev",
                    "rules": list(rules_seen.values()),
                }},
                "results": results,
                "invocations": [{
                    "executionSuccessful": len(errors) == 0,
                    "toolExecutionNotifications": [
                        {"message": {"text": e}, "level": "error"} for e in errors
                    ],
                }],
                "properties": {
                    "crossguard:version": _TOOL_VERSION,
                    "crossguard:timestamp": datetime.now(timezone.utc).isoformat(),
                },
            }],
        }
        return json.dumps(sarif, indent=2)

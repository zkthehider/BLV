import json
import requests
from typing import Dict, Any, List
from retrieval.vector_store import retrieve_for_agent_role

OLLAMA_API = "http://localhost:11434/api/chat"
GEN_MODEL = "qwen3:4b"

def evaluate_telemetry(module_description: str, telemetry_log: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compares observed HTTP telemetry against RAG security policies and evidence oracles."""
    rag_context = retrieve_for_agent_role(module_description, role="defensive", n_results=4)
    context_text = "\n\n".join(
        [f"[{rid}]\n{doc}" for rid, doc in zip(rag_context["ids"], rag_context["documents"])]
    )

    prompt = f"""You are an Application Security Auditor evaluating HTTP telemetry from a local DVWA test run.
Compare the observed HTTP responses against the defensive invariants and verification oracles from the knowledge base.

OBSERVED HTTP TELEMETRY:
{json.dumps(telemetry_log, indent=2)}

DEFENSIVE POLICIES & EVIDENCE ORACLES:
{context_text}

Return ONLY valid JSON with this exact schema:
{{
  "invariant_violated": true or false,
  "matched_cwe": "CWE-XXX",
  "evidence_summary": "Specific status codes, latency patterns, or state anomalies observed",
  "remediation_policy": "Summary of the required defensive invariant",
  "cited_docs": ["Doc ID 1", "Doc ID 2"]
}}"""

    response = requests.post(
        OLLAMA_API,
        json={
            "model": GEN_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1, "num_ctx": 4096}
        },
        timeout=120
    )

    raw_content = response.json().get("message", {}).get("content", "{}")
    return json.loads(raw_content)
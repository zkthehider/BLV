import sys
import json
import requests
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from retrieval.vector_store import retrieve_for_agent_role

OLLAMA_API = "http://localhost:11434/api/chat"
GEN_MODEL = "qwen3:4b"

def generate_audit_plan(module_description: str, endpoint: str) -> Dict[str, Any]:
    """Queries RAG for testing methodologies and outputs a structured JSON test plan."""
    rag_context = retrieve_for_agent_role(module_description, role="offensive", n_results=4)
    context_text = "\n\n".join(
        [f"[{rid}]\n{doc}" for rid, doc in zip(rag_context["ids"], rag_context["documents"])]
    )

    prompt = f"""You are a Security Quality Assurance Architect auditing a local DVWA lab module.
Based ONLY on the retrieved methodology context, design a structured state-audit plan to test whether the endpoint enforces business logic invariants.

TARGET ENDPOINT: {endpoint}
MODULE CONTEXT: {module_description}

KNOWLEDGE BASE CONTEXT:
{context_text}

Return ONLY valid JSON with this exact schema:
{{
  "target_cwe": "CWE-XXX",
  "hypothesis": "Description of the business logic assumption being tested",
  "audit_steps": [
    {{
      "step_name": "Baseline or perturbation check",
      "method": "GET or POST",
      "params_or_data": {{"key": "value"}},
      "expected_invariant": "What a secure implementation must enforce"
    }}
  ],
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
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

def generate_audit_plan(endpoint_profile: Dict[str, Any]) -> Dict[str, Any]:
    """Infers endpoint business function from raw DOM state, queries RAG, and builds an audit plan."""
    
    # Phase 1: Infer business purpose and generate a RAG search query from raw HTTP state
    inference_prompt = f"""You are an autonomous Application Security Architect analyzing an unknown web endpoint from its raw HTTP profile.

RAW ENDPOINT PROFILE:
{json.dumps(endpoint_profile, indent=2)}

TASK:
1. Classify the primary business archetype of this endpoint (e.g., Authentication Gate, Credential/Profile Mutation, Financial/Cart Transaction, Resource Lookup, File Ingestion, Multi-Stage Wizard) based strictly on its HTTP methods, headings, and input field names/types.
2. Identify the structural primitives present (e.g., password fields, hidden state parameters, numeric fields, object IDs, file inputs, anti-automation tokens).
3. Formulate 2 to 3 distinct, ranked business logic hypotheses across different architectural dimensions (such as Interaction Frequency/Rate Limits, Concurrency/Atomicity, Workflow Sequencing, Ownership/Access Control, or Numeric/Boundary Validation) without assuming only one flaw type exists.
4. For each hypothesis, generate a targeted search query for our security knowledge base.

Return ONLY valid JSON matching this schema:
{{
  "endpoint_archetype": "...",
  "observed_primitives": ["..."],
  "hypotheses": [
    {{
      "rank": 1,
      "category": "e.g., Interaction Frequency | Workflow Sequencing | Concurrency | Ownership | Input Bounds",
      "rationale": "Why this structural profile warrants testing this invariant",
      "rag_search_query": "..."
    }}
  ]
}}"""
    print(inference_prompt)

    ######### Ollama / Chatgpt Api #################
    # inf_res = requests.post(
    #     OLLAMA_API,
    #     json={
    #         "model": GEN_MODEL,
    #         "messages": [{"role": "user", "content": inference_prompt}],
    #         "format": "json",
    #         "stream": False,
    #         "options": {"temperature": 0.1, "num_ctx": 4096}
    #     },
    #     timeout=120
    # )
    ######### Ollama / Chatgpt Api #################

    inf_res = {
      "endpoint_archetype": "Credential/Profile Mutation (Password Change) with Potential Multi-Stage CAPTCHA Verification Workflow",
      "observed_primitives": [
        "HTTP POST method indicates a state-changing operation.",
        "Two password input fields: password_new and password_conf, suggesting new-password entry and confirmation.",
        "Hidden state parameter: step=1, indicating potential multi-stage workflow sequencing.",
        "Submit control: Change, triggering the password modification operation.",
        "Form action '#' indicates submission to the current endpoint.",
        "No visible CAPTCHA token, challenge response, or anti-automation parameter in the observed form.",
        "No numeric business input, object identifier, file input, or explicit ownership reference observed.",
        "PHPSESSID session cookie indicates session-based state management.",
        "security=low cookie indicates an application security-level configuration.",
        "HTTP 200 indicates successful page retrieval but does not establish successful password modification or validation."
      ],
      "hypotheses": [
        {
          "rank": 1,
          "category": "Workflow Sequencing",
          "rationale": "The hidden step=1 parameter and CAPTCHA-related endpoint heading suggest a potentially multi-stage verification workflow. The application may rely on client-controlled workflow state without independently enforcing CAPTCHA completion before allowing password modification. Test whether subsequent workflow stages can be reached or submitted without satisfying the intended CAPTCHA verification, and whether changing or omitting the step parameter violates server-side state-transition invariants.",
          "rag_search_query": "Business logic vulnerabilities in multi-stage CAPTCHA verification workflows, client-controlled hidden step parameters, password change workflow sequencing, server-side state transition enforcement, and bypass of mandatory CAPTCHA verification."
        },
        {
          "rank": 2,
          "category": "Interaction Frequency | Rate Limits",
          "rationale": "The endpoint exposes a password-changing operation and its heading identifies CAPTCHA as a security mechanism. CAPTCHA is intended to mitigate automated interactions, but its presence alone does not establish effective enforcement. Investigate whether CAPTCHA verification is bound to each password-change attempt, whether failed attempts are rate-limited, and whether repeated submissions can bypass intended anti-automation controls.",
          "rag_search_query": "Business logic vulnerabilities involving CAPTCHA bypass, missing server-side CAPTCHA validation, password change endpoint rate limiting, repeated password modification attempts, anti-automation enforcement, and CAPTCHA token reuse."
        },
        {
          "rank": 3,
          "category": "Concurrency | Atomicity",
          "rationale": "Password modification involves multiple related inputs and potentially multiple workflow stages. Concurrent or repeated submissions could expose inconsistent state handling if CAPTCHA verification, password confirmation, and credential mutation are not enforced as one logically consistent operation. Investigate whether verification state can be reused across requests or whether concurrent submissions produce inconsistent password-change outcomes.",
          "rag_search_query": "Business logic vulnerabilities in password change transaction atomicity, concurrent password modification requests, CAPTCHA verification state reuse, race conditions in multi-step authentication workflows, and inconsistent server-side session state."
        }
      ]
    }
    # inference = json.loads(inf_res.get("message", {}).get("content", "{}"))
    inference = inf_res

    # Phase 2: Query RAG across all top-ranked hypotheses
    aggregated_docs = []
    seen_ids = set()
    queries_used = []

    for hyp in inference.get("hypotheses", [])[:2]:
        print(hyp)
        q = hyp.get("rag_search_query", "")
        if not q:
            continue
        queries_used.append(q)
        rag_res = retrieve_for_agent_role(q, role="offensive", n_results=2)
        for rid, doc in zip(rag_res["ids"], rag_res["documents"]):
            if rid not in seen_ids:
                seen_ids.add(rid)
                aggregated_docs.append(f"[{rid} | Hypothesis: {hyp.get('category')}]\n{doc}")

    context_text = "\n\n".join(aggregated_docs)

    # Phase 3: Generate concrete state-auditing steps
    plan_prompt = f"""You are a Security QA Architect auditing an endpoint based on its observed state and retrieved testing methodologies.

ENDPOINT STATE PROFILE:
{json.dumps(endpoint_profile, indent=2)}

MULTI-HYPOTHESIS ANALYSIS:
{json.dumps(inference, indent=2)}

RETRIEVED TESTING METHODS & SCENARIOS:
{context_text}

Design a safe, structured state-audit plan covering the top hypotheses to verify whether the server enforces business logic invariants on this endpoint.
Return ONLY valid JSON matching this exact schema:
{{
  "inferred_function": "{inference.get('endpoint_archetype', 'Unknown Endpoint')}",
  "rag_queries_used": {json.dumps(queries_used)},
  "target_cwes": ["CWE-XXX"],
  "audit_steps": [
    {{
      "hypothesis_category": "Category from Phase 1 (e.g., Workflow Sequencing)",
      "step_name": "Descriptive name of the boundary or state check",
      "method": "GET or POST",
      "params_or_data": {{"param": "value"}},
      "expected_invariant": "What a secure backend must enforce"
    }}
  ],
  "cited_docs": ["Doc ID 1", "Doc ID 2"]
}}"""
    print(plan_prompt)

    # plan_res = requests.post(
    #     OLLAMA_API,
    #     json={
    #         "model": GEN_MODEL,
    #         "messages": [{"role": "user", "content": plan_prompt}],
    #         "format": "json",
    #         "stream": False,
    #         "options": {"temperature": 0.1, "num_ctx": 4096}
    #     },
    #     timeout=120
    # )
    # return json.loads(plan_res.json().get("message", {}).get("content", "{}"))
    return json.loads("""{
  "inferred_function": "Credential/Profile Mutation (Password Change) with Potential Multi-Stage CAPTCHA Verification Workflow",
  "rag_queries_used": [
    "Business logic vulnerabilities in multi-stage CAPTCHA verification workflows, client-controlled hidden step parameters, password change workflow sequencing, server-side state transition enforcement, and bypass of mandatory CAPTCHA verification.",
    "Business logic vulnerabilities involving CAPTCHA bypass, missing server-side CAPTCHA validation, password change endpoint rate limiting, repeated password modification attempts, anti-automation enforcement, and CAPTCHA token reuse."
  ],
  "target_cwes": [
    "CWE-841",
    "CWE-307",
    "CWE-799",
    "CWE-602",
    "CWE-346"
  ],
  "audit_steps": [
    {
      "hypothesis_category": "Workflow Sequencing",
      "step_name": "Baseline Password Change State Transition",
      "method": "POST",
      "params_or_data": {
        "step": "1",
        "password_new": "<controlled-test-password>",
        "password_conf": "<controlled-test-password>",
        "Change": "Change"
      },
      "expected_invariant": "The backend must enforce the documented password-change workflow, validate all required prerequisites, and distinguish successful credential mutation from an HTTP 200 page response. Establish the baseline using a dedicated test account and verify the resulting credential state."
    },
    {
      "hypothesis_category": "Workflow Sequencing",
      "step_name": "Prerequisite Verification and State Desynchronization",
      "method": "POST",
      "params_or_data": {
        "step": "2",
        "password_new": "<controlled-test-password>",
        "password_conf": "<controlled-test-password>",
        "Change": "Change"
      },
      "expected_invariant": "A later workflow stage must not execute unless its required preceding verification stages have completed successfully. The server must maintain authoritative workflow state rather than trusting a client-controlled hidden step parameter. No password modification should occur when CAPTCHA verification or other required prerequisites are incomplete."
    },
    {
      "hypothesis_category": "Workflow Sequencing",
      "step_name": "Hidden Workflow Parameter Tampering",
      "method": "POST",
      "params_or_data": {
        "step": "0",
        "password_new": "<controlled-test-password>",
        "password_conf": "<controlled-test-password>",
        "Change": "Change"
      },
      "expected_invariant": "The backend must reject unsupported, unexpected, missing, or out-of-order workflow states. Modifying the hidden step parameter must not bypass CAPTCHA validation or trigger an unauthorized password change."
    },
    {
      "hypothesis_category": "Workflow Sequencing",
      "step_name": "CAPTCHA Verification Replay",
      "method": "POST",
      "params_or_data": {
        "step": "2",
        "password_new": "<controlled-test-password>",
        "password_conf": "<controlled-test-password>",
        "Change": "Change"
      },
      "expected_invariant": "CAPTCHA verification must be validated server-side, bound to the appropriate session and operation, and invalidated or consumed according to the intended workflow. Previously consumed, expired, or unrelated verification state must not authorize another password change."
    },
    {
      "hypothesis_category": "Interaction Frequency | Rate Limits",
      "step_name": "Controlled Invalid Attempt Threshold Calibration",
      "method": "POST",
      "params_or_data": {
        "step": "1",
        "password_new": "<controlled-test-password>",
        "password_conf": "<intentionally-mismatched-test-password>",
        "Change": "Change"
      },
      "expected_invariant": "Repeated invalid password-change attempts must be subject to appropriate server-side throttling or anti-automation controls. CAPTCHA enforcement must not exist exclusively in the browser interface. Failed-attempt counters and throttling must be enforced independently of client-side controls."
    },
    {
      "hypothesis_category": "Interaction Frequency | Rate Limits",
      "step_name": "Session-Based Rate Limit Persistence",
      "method": "POST",
      "params_or_data": {
        "step": "1",
        "password_new": "<controlled-test-password>",
        "password_conf": "<intentionally-mismatched-test-password>",
        "Change": "Change"
      },
      "expected_invariant": "Rate-limit enforcement must not be trivially reset by obtaining a new PHPSESSID or modifying client-controlled request headers. Attempt tracking should use appropriate server-side identity and session context. Test only a small, controlled number of requests."
    },
    {
      "hypothesis_category": "Interaction Frequency | Rate Limits",
      "step_name": "Bounded Concurrent Submission Consistency",
      "method": "POST",
      "params_or_data": {
        "step": "1",
        "password_new": "<controlled-test-password>",
        "password_conf": "<controlled-test-password>",
        "Change": "Change"
      },
      "expected_invariant": "A small number of concurrent submissions must not bypass verification requirements, produce multiple successful mutations, or cause inconsistent credential state. The server should serialize or safely coordinate state-changing operations and enforce applicable rate limits. Verify results using the dedicated test account."
    }
  ],
  "cited_docs": [
    "method_portswigger_blv_testing_001",
    "method_cwe_307_excessive_auth_auditing_001",
    "scenario_cwe_799_anti_automation_bypass_001"
  ]
}""")
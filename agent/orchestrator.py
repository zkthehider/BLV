import sys
import json
from pathlib import Path

# Anchor project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.dvwa_client import DVWAClient
from agent.planner import generate_audit_plan
from agent.verifier import evaluate_telemetry


def run_dvwa_blv_audit(base_url: str, endpoint: str, security_level: str = "low"):
    print(f"[*] Initializing DVWA Client (Security: {security_level})...")
    client = DVWAClient(base_url=base_url, security_level=security_level)

    if not client.authenticate():
        print("[!] Authentication to DVWA failed. Check URL and credentials.")
        return

    # 1. Blindly scrape the live endpoint DOM & state (zero human hints)
    print(f"[*] Profiling live state of {endpoint}...")
    endpoint_profile = client.profile_endpoint(endpoint)
    print(f"[+] Extracted Forms: {json.dumps(endpoint_profile.get('forms', []), indent=2)}")

    # 2. Let the AI Planner infer functionality from raw DOM state & query RAG
    print("[*] Inferring endpoint purpose and generating audit plan via RAG...")
    plan = generate_audit_plan(endpoint_profile)
    inferred_func = plan.get("inferred_function", "Unknown endpoint workflow")
    print(f"[+] Inferred Function: {inferred_func}")
    print(f"[+] Autonomous RAG Query: {plan.get('rag_query_used')}")
    print(f"[+] Audit Hypothesis ({plan.get('target_cwe')}): {plan.get('hypothesis')}")

    # 3. Execute the planned state transitions deterministically
    telemetry = []
    for step in plan.get("audit_steps", []):
        print(f"    -> Executing step: {step.get('step_name')}")
        method = step.get("method", "GET")
        params_or_data = step.get("params_or_data", {})

        result = client.send_audit_request(
            endpoint=endpoint,
            method=method,
            params=params_or_data if method.upper() == "GET" else None,
            data=params_or_data if method.upper() == "POST" else None
        )
        result["step_name"] = step.get("step_name")
        telemetry.append(result)
    print(telemetry)
    # 4. Evaluate telemetry against RAG defensive policies & evidence oracles
    # print("[*] Evaluating telemetry against RAG Evidence Oracles...")
    # verdict = evaluate_telemetry(inferred_func, telemetry)
    # print("\n=== AUDIT VERDICT ===")
    # print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    run_dvwa_blv_audit(
        base_url="http://localhost/DVWA",
        endpoint="/vulnerabilities/captcha/",
        security_level="low"
    )
import json
from dvwa_client import DVWAClient
from planner import generate_audit_plan
from verifier import evaluate_telemetry

def run_dvwa_blv_audit(base_url: str, endpoint: str, description: str, security_level: str = "low"):
    print(f"[*] Initializing DVWA Client (Security: {security_level})...")
    client = DVWAClient(base_url=base_url, security_level=security_level)
    
    if not client.authenticate():
        print("[!] Authentication to DVWA failed. Check URL and credentials.")
        return

    print(f"[*] Querying RAG Planner for {endpoint}...")
    plan = generate_audit_plan(description, endpoint)
    print(f"[+] Audit Hypothesis ({plan.get('target_cwe')}): {plan.get('hypothesis')}")

    telemetry = []
    for step in plan.get("audit_steps", []):
        print(f"    -> Executing step: {step.get('step_name')}")
        method = step.get("method", "GET")
        params_or_data = step.get("params_or_data", {})
        
        result = client.send_audit_request(
            endpoint=endpoint,
            method=method,
            params=params_or_data if method == "GET" else None,
            data=params_or_data if method == "POST" else None
        )
        result["step_name"] = step.get("step_name")
        telemetry.append(result)

    print("[*] Evaluating telemetry against RAG Evidence Oracles...")
    verdict = evaluate_telemetry(description, telemetry)
    print("\n=== AUDIT VERDICT ===")
    print(json.dumps(verdict, indent=2))

if __name__ == "__main__":
    # Example: Auditing DVWA's multi-step CAPTCHA workflow for step-skipping (CWE-841)
    run_dvwa_blv_audit(
        base_url="http://localhost/DVWA",
        endpoint="/vulnerabilities/authbypass/",
        description="Multi-step password reset workflow with step=1 verification and step=2 confirmation",
        security_level="low"
    )
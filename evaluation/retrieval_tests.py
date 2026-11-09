import sys
from pathlib import Path

# Anchor project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import time
import json
import requests
from retrieval.vector_store import retrieve_balanced_across_files, retrieve_for_agent_role

OLLAMA_API = "http://localhost:11434/api/chat"
GEN_MODEL = "qwen3:4b"

# ----------------------------------------------------------------------
# 1. Retrieval Distribution & Latency Benchmark
# ----------------------------------------------------------------------
def test_balanced_retrieval_benchmark():
    query = "Concurrent execution bypassing promotional voucher usage limits and multi-spend"
    print(f"\n{'='*75}\n[TEST 1] Balanced Partition Retrieval Benchmark (2 records/file = 10 total)\n{'='*75}")
    
    start_time = time.perf_counter()
    res = retrieve_balanced_across_files(query, records_per_file=2)
    latency_ms = (time.perf_counter() - start_time) * 1000

    print(f"Total Records Retrieved: {res['total_retrieved']} | Query Latency: {latency_ms:.2f} ms\n")
    
    type_counts = {}
    print(f"{'Source Type':<22} | {'Record ID':<50} | {'Title'}")
    print("-" * 100)
    for doc_id, meta in zip(res["ids"], res["metadatas"]):
        stype = meta.get("source_type", "unknown")
        title = meta.get("title", "N/A")[:35]
        type_counts[stype] = type_counts.get(stype, 0) + 1
        print(f"{stype:<22} | {doc_id:<50} | {title}")

    print("\nPartition Verification:")
    for stype, count in type_counts.items():
        status = "PASS" if count == 2 else "FAIL"
        print(f"  [{status}] {stype}: {count}/2 records")

    return res

# ----------------------------------------------------------------------
# 2. Targeted Category Query Benchmark
# ----------------------------------------------------------------------
def test_category_filtering_benchmark():
    print(f"\n{'='*75}\n[TEST 2] Category Filtered Retrieval (Auditing vs. Probing contexts)\n{'='*75}")
    query = "State sequence subversion and skipping intermediate validation stages"
    
    # Audit mode: Policies and Evidence
    print("\n--- Auditing Context (security_policies + evidence_patterns) ---")
    audit_res = retrieve_for_agent_role(query, role="defensive", n_results=4)
    for rid, meta in zip(audit_res["ids"], audit_res["metadatas"]):
        print(f"  - [{meta['source_type']}] {rid} -> {meta.get('title')}")

    # Probing mode: Attack Scenarios and Testing Methods
    print("\n--- Probing Context (attack_scenarios + testing_methods) ---")
    probe_res = retrieve_for_agent_role(query, role="offensive", n_results=4)
    for rid, meta in zip(probe_res["ids"], probe_res["metadatas"]):
        print(f"  - [{meta['source_type']}] {rid} -> {meta.get('title')}")

# ----------------------------------------------------------------------
# 3. LLM Synthesis Evaluation Over 10 Balanced Records
# ----------------------------------------------------------------------
def test_llm_synthesis_over_balanced_kb(retrieved_data):
    print(f"\n{'='*75}\n[TEST 3] LLM Synthesis Over Complete 10-Record Partitioned Context\n{'='*75}")
    query = "Explain how TOCTOU race conditions manifest in voucher redemptions, what invariant must be enforced, and what oracle verifies the defect."
    
    context_blocks = "\n\n".join(
        [f"[Doc ID: {rid}]\n{doc}" for rid, doc in zip(retrieved_data["ids"], retrieved_data["documents"])]
    )

    prompt = f"""You are an Application Security Architect. Answer the question strictly using the provided context.
    
CONTEXT:
{context_blocks}

QUESTION:
{query}

TASK:
1. State the exact vulnerability classification and root cause.
2. Provide the formal defensive invariant or policy constraint that must hold.
3. Provide the verification oracle or evidence formula to prove the vulnerability.
4. Reference the specific [Doc ID] for each point."""

    payload = {
        "model": GEN_MODEL,
        "messages": [
            {"role": "system", "content": "Answer strictly based on the provided technical security context."},
            {"role": "user", "content": prompt}
        ],
        "stream": True,
        "options": {"temperature": 0.2, "num_ctx": 8192}
    }

    print("\n--- LLM Response ---")
    try:
        response = requests.post(OLLAMA_API, json=payload, stream=True, timeout=180)
        is_thinking = False

        for line in response.iter_lines():
            if not line:
                continue
            chunk = json.loads(line.decode("utf-8"))
            msg = chunk.get("message", {})

            thinking = msg.get("thinking", "")
            content = msg.get("content", "")

            if thinking:
                if not is_thinking:
                    sys.stdout.write("\n[Reasoning]: ")
                    is_thinking = True
                sys.stdout.write(thinking)
                sys.stdout.flush()

            if content:
                if is_thinking:
                    sys.stdout.write("\n\n[Answer]:\n")
                    is_thinking = False
                sys.stdout.write(content)
                sys.stdout.flush()

            if chunk.get("done", False):
                break
        print("\n")
    except Exception as e:
        print(f"[ERROR]: {e}")

if __name__ == "__main__":
    balanced_res = test_balanced_retrieval_benchmark()
    test_category_filtering_benchmark()
    test_llm_synthesis_over_balanced_kb(balanced_res)
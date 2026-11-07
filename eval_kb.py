import chromadb
from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
import json
import requests
import sys

OLLAMA_CHAT_API = "http://localhost:11434/api/chat"
GEN_MODEL = "qwen3:4b"  # Set to your exact installed model name
COLLECTION_NAME = "appsec_business_logic_kb"

def ask_local_llm(query: str, retrieved_docs: list, retrieved_ids: list, disable_thinking: bool = False):
    context_blocks = "\n\n".join(
        [f"[Doc ID: {doc_id}]\n{doc}" for doc_id, doc in zip(retrieved_ids, retrieved_docs)]
    )

    system_instruction = (
        "You are an Application Security Architect. Answer questions strictly using the "
        "provided context. If the answer cannot be determined from the context, state that it is not covered."
    )

    user_content = f"""CONTEXT:
{context_blocks}

QUESTION:
{query}

TASK:
1. Provide the exact vulnerability classification and root cause.
2. Specify the formal defensive invariant or policy constraint that must hold.
3. List the test oracle or evidence pattern to verify this flaw.
4. Reference the specific [Doc ID] you used for each assertion."""

    payload = {
        "model": GEN_MODEL,
        "messages": [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": user_content}
        ],
        "stream": True,  # Enables real-time streaming
        "options": {
            "temperature": 0.2,
            "num_ctx": 4096
        }
    }

    # Bypasses thinking tokens if supported by your Ollama version
    if disable_thinking:
        payload["think"] = False

    try:
        response = requests.post(OLLAMA_CHAT_API, json=payload, stream=True, timeout=180)
        
        if response.status_code != 200:
            print(f"[ERROR {response.status_code}]: {response.text}")
            return

        full_content = []
        is_thinking = False

        for line in response.iter_lines():
            if not line:
                continue
            
            chunk = json.loads(line.decode("utf-8"))
            msg = chunk.get("message", {})

            # Handle thinking tokens separately if present in the message payload
            thinking_token = msg.get("thinking", "")
            content_token = msg.get("content", "")

            if thinking_token:
                if not is_thinking:
                    sys.stdout.write("\n[Reasoning]: ")
                    is_thinking = True
                sys.stdout.write(thinking_token)
                sys.stdout.flush()

            if content_token:
                if is_thinking:
                    sys.stdout.write("\n\n[Answer]:\n")
                    is_thinking = False
                sys.stdout.write(content_token)
                sys.stdout.flush()
                full_content.append(content_token)

            if chunk.get("done", False):
                break

        print("\n")
        return "".join(full_content)

    except requests.exceptions.Timeout:
        print("\n[ERROR]: Request timed out.")
    except Exception as e:
        print(f"\n[ERROR]: {e}")

def query_knowledge_base(query: str, n_results: int = 4):
    ollama_ef = OllamaEmbeddingFunction(
        model_name="nomic-embed-text",
        url="http://localhost:11434"
    )
    client = chromadb.PersistentClient(path="./chroma_db")
    collection = client.get_collection(name=COLLECTION_NAME, embedding_function=ollama_ef)
    
    results = collection.query(query_texts=[query], n_results=n_results)
    return results


def run_test_suite():
    test_cases = [
        {
            "name": "TOCTOU Multi-Spend / Coupon Stacking",
            "query": "How do we prevent concurrent requests from exploiting single-use voucher codes, and what is the verification oracle for proving the flaw?",
            "expected_cwe": "CWE-367",
            "expected_types": ["security_policies", "evidence_patterns"]
        },
        {
            "name": "Behavioral Workflow Circumvention",
            "query": "What occurs when an attacker skips intermediate verification steps to reach terminal endpoints directly, and how should multi-step state machines be enforced?",
            "expected_cwe": "CWE-841",
            "expected_types": ["vulnerabilities", "security_policies"]
        },
        {
            "name": "Excessive Interaction & Anti-Automation",
            "query": "Why are serialized thread sleep delays insufficient for brute-force protection, and what weakness class governs interaction frequency?",
            "expected_cwe": "CWE-307",
            "expected_types": ["vulnerabilities", "testing_methods"]
        }
    ]

    for tc in test_cases:
        print(f"\n{'='*70}\n[TEST CASE]: {tc['name']}\n{'='*70}")
        query = tc["query"]
        results = query_knowledge_base(query, n_results=4)

        retrieved_ids = results["ids"][0]
        retrieved_docs = results["documents"][0]
        retrieved_metas = results["metadatas"][0]

        print("\n--- RETRIEVED CHUNKS ---")
        for rid, meta in zip(retrieved_ids, retrieved_metas):
            print(f"- ID: {rid} | Type: {meta['source_type']} | Class: {meta['vulnerability_class']}")

        print("\n--- LLM SYNTHESIS (via Ollama) ---")
        answer = ask_local_llm(query, retrieved_docs, retrieved_ids)
        print(answer)

if __name__ == "__main__":
    run_test_suite()
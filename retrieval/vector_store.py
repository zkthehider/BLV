from pathlib import Path
from typing import List, Dict, Any, Optional
import chromadb
from chromadb.utils.embedding_functions import OllamaEmbeddingFunction

COLLECTION_NAME = "appsec_business_logic_kb"
OLLAMA_URL = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"

ALL_FILE_TYPES = [
    "vulnerabilities",
    "attack_scenarios",
    "security_policies",
    "testing_methods",
    "evidence_patterns",
]

def get_collection(persist_path: str = "./chroma_db"):
    ollama_ef = OllamaEmbeddingFunction(
        model_name=EMBED_MODEL,
        url=OLLAMA_URL
    )
    client = chromadb.PersistentClient(path=persist_path)
    return client.get_collection(name=COLLECTION_NAME, embedding_function=ollama_ef)

# ----------------------------------------------------------------------
# 1. Balanced Partitioned Retrieval (2 records per file = 10 total)
# ----------------------------------------------------------------------
def retrieve_balanced_across_files(
    query: str, 
    records_per_file: int = 2,
    target_types: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Queries ChromaDB by filtering on each source_type partition,
    ensuring a balanced distribution of records for performance benchmarks.
    """
    collection = get_collection()
    types_to_query = target_types or ALL_FILE_TYPES

    aggregated_ids = []
    aggregated_docs = []
    aggregated_metas = []

    for source_type in types_to_query:
        # ChromaDB metadata filter using $eq operator
        res = collection.query(
            query_texts=[query],
            n_results=records_per_file,
            where={"source_type": {"$eq": source_type}}
        )

        if res["ids"] and res["ids"][0]:
            aggregated_ids.extend(res["ids"][0])
            aggregated_docs.extend(res["documents"][0])
            aggregated_metas.extend(res["metadatas"][0])

    return {
        "ids": aggregated_ids,
        "documents": aggregated_docs,
        "metadatas": aggregated_metas,
        "total_retrieved": len(aggregated_ids)
    }

# ----------------------------------------------------------------------
# 2. Agent Role-Based Filtered Retrieval
# ----------------------------------------------------------------------
def retrieve_for_agent_role(
    query: str,
    role: str = "offensive",
    n_results: int = 5
) -> Dict[str, Any]:
    """
    Retrieves filtered contexts suited to the HTTP agent's operational stage:
    - 'offensive' / 'probe': attack_scenarios & testing_methods
    - 'defensive' / 'audit': security_policies & evidence_patterns
    - 'triage': vulnerabilities, security_policies, & evidence_patterns
    """
    collection = get_collection()

    role_mapping = {
        "offensive": ["attack_scenarios", "testing_methods"],
        "defensive": ["security_policies", "evidence_patterns"],
        "triage": ["vulnerabilities", "security_policies", "evidence_patterns"]
    }

    allowed_types = role_mapping.get(role.lower(), ALL_FILE_TYPES)

    # Use ChromaDB $in filter to fetch directly from the target subsets
    where_filter = {"source_type": {"$in": allowed_types}}

    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        where=where_filter
    )

    return {
        "ids": results["ids"][0] if results["ids"] else [],
        "documents": results["documents"][0] if results["documents"] else [],
        "metadatas": results["metadatas"][0] if results["metadatas"] else [],
        "role": role,
        "allowed_types": allowed_types
    }
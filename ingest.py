import json
import glob
from pathlib import Path
import chromadb
from chromadb.utils.embedding_functions import OllamaEmbeddingFunction

DATA_DIR = Path("data/processed")
COLLECTION_NAME = "appsec_business_logic_kb"

def load_records(data_path: Path):
    documents = []
    metadatas = []
    ids = []

    for file_path in glob.glob(str(data_path / "*.jsonl")):
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                
                # Context-rich embedding text: prepend structural context to text
                doc_text = f"[{record.get('source_type', '').upper()} | {record.get('domain', '')}] {record.get('text', '')}"
                
                # Flatten metadata so ChromaDB can store it as primitive types
                meta = {
                    "source_type": record.get("source_type", ""),
                    "domain": record.get("domain", ""),
                    "title": record.get("metadata", {}).get("title", ""),
                    "source": record.get("metadata", {}).get("source", ""),
                    "vulnerability_class": record.get("metadata", {}).get("vulnerability_class", ""),
                }
                
                documents.append(doc_text)
                metadatas.append(meta)
                ids.append(record["id"])

    return ids, documents, metadatas

def main():
    # Uses Ollama locally to generate vector embeddings
    ollama_ef = OllamaEmbeddingFunction(
        model_name="nomic-embed-text",
        url="http://localhost:11434"
    )

    client = chromadb.PersistentClient(path="./chroma_db")
    
    # Reset collection for clean testing
    try:
        client.delete_collection(name=COLLECTION_NAME)
    except Exception:
        pass

    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=ollama_ef,
        metadata={"hnsw:space": "cosine"}
    )

    ids, docs, metas = load_records(DATA_DIR)
    print(f"Loaded {len(ids)} curated records across datasets.")

    # Batch insert into ChromaDB
    batch_size = 50
    for i in range(0, len(ids), batch_size):
        collection.add(
            ids=ids[i:i+batch_size],
            documents=docs[i:i+batch_size],
            metadatas=metas[i:i+batch_size]
        )
    print("Ingestion complete. Chroma index persisted.")

if __name__ == "__main__":
    main()
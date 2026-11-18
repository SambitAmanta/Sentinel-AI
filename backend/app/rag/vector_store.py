"""ChromaDB Vector Store for CWE Security Knowledge and Semantic Mitigation Retrieval."""
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import chromadb
from app.rag.knowledge_base import CWE_KNOWLEDGE_DOCS

logger = logging.getLogger(__name__)

class CWEVectorStore:
    """Manages local ChromaDB vector indexing and semantic similarity search for security guidance."""

    COLLECTION_NAME = "cwe_security_knowledge"

    def __init__(self, persist_dir: Optional[Path] = None):
        self.persist_dir = persist_dir or (Path(__file__).resolve().parent.parent.parent / "chroma_db")
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize persistent ChromaDB client
        self.client = chromadb.PersistentClient(path=str(self.persist_dir))
        self.collection = self._init_collection()

    def _init_collection(self):
        """Initializes and seeds collection with CWE remediation guidelines."""
        collection = self.client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={"description": "CWE security remediation guidelines and patch patterns"}
        )
        
        # Check if already populated
        existing_count = collection.count()
        if existing_count < len(CWE_KNOWLEDGE_DOCS):
            logger.info(f"Seeding ChromaDB CWE vector store ({len(CWE_KNOWLEDGE_DOCS)} documents)...")
            ids = [doc["id"] for doc in CWE_KNOWLEDGE_DOCS]
            documents = [f"{doc['title']}\n\n{doc['text']}" for doc in CWE_KNOWLEDGE_DOCS]
            metadatas = [doc["metadata"] for doc in CWE_KNOWLEDGE_DOCS]
            
            # Upsert into collection
            collection.upsert(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )
            logger.info("ChromaDB vector indexing complete.")
            
        return collection

    def query_guidance(
        self,
        query: str,
        cwe_id: Optional[str] = None,
        n_results: int = 2
    ) -> List[Dict[str, Any]]:
        """Queries the vector store for semantic remediation guidance."""
        where_filter = None
        if cwe_id:
            # Normalize CWE format: e.g. "CWE-89"
            cwe_clean = cwe_id.upper().strip()
            if not cwe_clean.startswith("CWE-"):
                cwe_clean = f"CWE-{cwe_clean}"
            where_filter = {"cwe_id": cwe_clean}

        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=min(n_results, self.collection.count() or 1),
                where=where_filter
            )
        except Exception as e:
            # If filtered query returns empty or fails, retry without filter
            logger.warning(f"Filtered vector query failed: {e}. Retrying without filter...")
            results = self.collection.query(
                query_texts=[query],
                n_results=min(n_results, self.collection.count() or 1)
            )

        items = []
        if results and results.get("documents") and results["documents"][0]:
            docs = results["documents"][0]
            metas = results["metadatas"][0] if results.get("metadatas") else [{}] * len(docs)
            ids = results["ids"][0] if results.get("ids") else [""] * len(docs)
            distances = results["distances"][0] if results.get("distances") else [0.0] * len(docs)

            for doc_id, doc_text, meta, dist in zip(ids, docs, metas, distances):
                items.append({
                    "id": doc_id,
                    "document": doc_text,
                    "metadata": meta,
                    "distance": round(float(dist), 4),
                    "relevance_score": round(max(0.0, 1.0 - float(dist)), 4)
                })

        return items

    def format_guidance_for_prompt(self, items: List[Dict[str, Any]]) -> str:
        """Formats retrieved vector RAG items into a clean markdown block for LLM prompt context."""
        if not items:
            return ""

        blocks = []
        for i, item in enumerate(items, 1):
            meta = item.get("metadata", {})
            cwe = meta.get("cwe_id", "Unknown CWE")
            driver = meta.get("driver", "General")
            doc = item.get("document", "").strip()
            score = item.get("relevance_score", 0.0)
            blocks.append(f"### [RAG Guidance #{i} | {cwe} ({driver}) | Relevance: {score:.2f}]\n{doc}")

        return "\n\n".join(blocks)

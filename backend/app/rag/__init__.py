"""RAG (Retrieval-Augmented Generation) System for Cybersecurity Knowledge."""

import hashlib
import json
import os
from datetime import datetime
from typing import Any

import numpy as np
from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class DocumentChunk(BaseModel):
    """A chunk of a document for RAG retrieval."""

    chunk_id: str
    document_id: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str = ""
    source_type: str = ""  # mitre, cve, article, playbook
    version: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    embedding: list[float] | None = None


class RetrievalResult(BaseModel):
    """Result from RAG retrieval."""

    chunk: DocumentChunk
    similarity_score: float
    rank: int


class RAGQuery(BaseModel):
    """Query for RAG retrieval."""

    query_text: str
    top_k: int = 5
    min_similarity: float = 0.5
    filters: dict[str, Any] = Field(default_factory=dict)


class RAGResponse(BaseModel):
    """Response from RAG system."""

    query: str
    results: list[RetrievalResult] = Field(default_factory=list)
    context: str = ""
    total_chunks_searched: int = 0
    retrieval_time_ms: float = 0.0


class EmbeddingProvider:
    """Base embedding provider interface."""

    def embed_text(self, text: str) -> list[float]:
        """Generate embedding for text."""
        raise NotImplementedError

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for batch of texts."""
        return [self.embed_text(t) for t in texts]


class SimpleEmbedding(EmbeddingProvider):
    """Simple TF-IDF-like embedding for testing (no external dependencies)."""

    def __init__(self, dim: int = 384):
        self.dim = dim
        self.vocab: dict[str, int] = {}

    def _tokenize(self, text: str) -> list[str]:
        """Simple tokenization."""
        import re

        text = text.lower()
        tokens = re.findall(r"\b\w+\b", text)
        return tokens

    def embed_text(self, text: str) -> list[float]:
        """Generate simple hash-based embedding."""
        tokens = self._tokenize(text)
        embedding = np.zeros(self.dim)

        for token in tokens:
            # Hash token to get consistent indices
            h = int(hashlib.md5(token.encode()).hexdigest(), 16)
            idx = h % self.dim
            embedding[idx] += 1.0

        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm

        return embedding.tolist()


class FAISSIndex:
    """FAISS-based vector index for RAG retrieval."""

    def __init__(self, dimension: int = 384, index_path: str | None = None):
        self.dimension = dimension
        self.index_path = index_path
        self.index = None
        self.chunks: list[DocumentChunk] = []
        self._initialized = False

        # Try to import faiss, fall back to numpy-based search
        try:
            import faiss

            self.faiss = faiss
            self.use_faiss = True
        except ImportError:
            self.faiss = None
            self.use_faiss = False
            self._vectors: list[np.ndarray] = []

    def initialize(self) -> None:
        """Initialize the index."""
        if self.use_faiss:
            self.index = self.faiss.IndexFlatIP(self.dimension)  # Inner product
        self._initialized = True

    def add_chunk(self, chunk: DocumentChunk) -> None:
        """Add a chunk to the index."""
        if not self._initialized:
            self.initialize()

        if chunk.embedding is None:
            raise ValueError("Chunk must have embedding")

        embedding = np.array(chunk.embedding, dtype=np.float32)

        if self.use_faiss:
            self.index.add(embedding.reshape(1, -1))
        else:
            self._vectors.append(embedding)

        self.chunks.append(chunk)

    def add_chunks(self, chunks: list[DocumentChunk]) -> None:
        """Add multiple chunks to the index."""
        for chunk in chunks:
            self.add_chunk(chunk)

    def search(
        self, query_embedding: list[float], top_k: int = 5
    ) -> list[tuple[int, float]]:
        """Search for similar chunks."""
        if not self._initialized or len(self.chunks) == 0:
            return []

        query = np.array(query_embedding, dtype=np.float32).reshape(1, -1)

        if self.use_faiss:
            scores, indices = self.index.search(query, min(top_k, len(self.chunks)))
            return [(int(idx), float(score)) for idx, score in zip(indices[0], scores[0]) if idx >= 0]
        else:
            # Numpy fallback
            vectors = np.array(self._vectors)
            scores = np.dot(vectors, query.T).flatten()
            top_indices = np.argsort(scores)[::-1][:top_k]
            return [(int(idx), float(scores[idx])) for idx in top_indices]

    def save(self, path: str) -> None:
        """Save index to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)

        # Save chunks metadata
        chunks_data = [c.model_dump() for c in self.chunks]
        with open(f"{path}_chunks.json", "w") as f:
            json.dump(chunks_data, f, default=str)

        if self.use_faiss and self.index is not None:
            self.faiss.write_index(self.index, f"{path}.faiss")
        else:
            # Save numpy vectors
            np.save(f"{path}_vectors.npy", np.array(self._vectors))

    def load(self, path: str) -> bool:
        """Load index from disk."""
        try:
            # Load chunks
            with open(f"{path}_chunks.json", "r") as f:
                chunks_data = json.load(f)
                self.chunks = [DocumentChunk(**c) for c in chunks_data]

            if self.use_faiss and os.path.exists(f"{path}.faiss"):
                self.index = self.faiss.read_index(f"{path}.faiss")
            elif os.path.exists(f"{path}_vectors.npy"):
                self._vectors = list(np.load(f"{path}_vectors.npy"))

            self._initialized = True
            return True
        except Exception:
            return False

    @property
    def size(self) -> int:
        """Number of chunks in index."""
        return len(self.chunks)


class CybersecurityRAG:
    """RAG system for cybersecurity knowledge retrieval."""

    def __init__(
        self,
        embedding_provider: EmbeddingProvider | None = None,
        index_path: str = "data/indexes/cybersecurity_rag",
    ):
        self.embedding_provider = embedding_provider or SimpleEmbedding()
        self.index_path = index_path
        self.index = FAISSIndex(dimension=384, index_path=index_path)

        # Knowledge categories
        self.knowledge_sources = {
            "mitre_attack": "MITRE ATT&CK Framework",
            "cve": "CVE Database",
            "playbooks": "Incident Response Playbooks",
            "best_practices": "Security Best Practices",
            "threat_intel": "Threat Intelligence",
        }

    def initialize(self) -> None:
        """Initialize RAG system."""
        self.index.initialize()

        # Try to load existing index
        if not self.index.load(self.index_path):
            # Load default knowledge base
            self._load_default_knowledge()

    def _load_default_knowledge(self) -> None:
        """Load default cybersecurity knowledge."""
        # MITRE ATT&CK knowledge
        mitre_knowledge = [
            {
                "id": "T1566",
                "name": "Phishing",
                "tactic": "Initial Access",
                "description": "Adversaries may send phishing messages to gain access to victim systems. Phishing involves social engineering techniques to trick users into clicking malicious links or opening attachments.",
                "mitigations": ["User training", "Email filtering", "Multi-factor authentication"],
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                "mitigations": ["Account lockout policies", "Multi-factor authentication", "Password complexity requirements"],
            },
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": "Adversaries may communicate using application layer protocols to avoid detection. Common protocols include HTTP/HTTPS, DNS, and SMTP.",
                "mitigations": ["Network intrusion detection", "SSL/TLS inspection", "DNS monitoring"],
            },
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "mitigations": ["Disable or remove unused interpreters", "Code signing", "Execution prevention"],
            },
            {
                "id": "T1048",
                "name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "description": "Adversaries may steal data by exfiltrating it over a different protocol than the existing command and control channel.",
                "mitigations": ["Network segmentation", "Data loss prevention", "Egress filtering"],
            },
            {
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": "Adversaries may encrypt data on target systems to interrupt availability. This is commonly associated with ransomware.",
                "mitigations": ["Data backup", "Behavior-based detection", "Application isolation"],
            },
        ]

        # Incident response playbooks
        playbooks = [
            {
                "name": "Phishing Response",
                "steps": [
                    "Identify and isolate affected systems",
                    "Block malicious URLs and sender addresses",
                    "Reset credentials for affected users",
                    "Scan for malware on affected systems",
                    "Review email logs for other recipients",
                    "Document incident and update filters",
                ],
            },
            {
                "name": "Ransomware Response",
                "steps": [
                    "Isolate affected systems immediately",
                    "Identify ransomware variant",
                    "Check for available decryption tools",
                    "Assess backup availability",
                    "Do not pay ransom without legal consultation",
                    "Restore from clean backups",
                    "Investigate initial access vector",
                ],
            },
            {
                "name": "Data Breach Response",
                "steps": [
                    "Contain the breach immediately",
                    "Assess scope of data exposure",
                    "Preserve evidence for investigation",
                    "Notify legal and compliance teams",
                    "Prepare breach notification if required",
                    "Remediate vulnerabilities",
                    "Implement additional monitoring",
                ],
            },
        ]

        # Add MITRE knowledge
        for technique in mitre_knowledge:
            content = f"""
MITRE ATT&CK Technique: {technique['id']} - {technique['name']}
Tactic: {technique['tactic']}
Description: {technique['description']}
Mitigations: {', '.join(technique['mitigations'])}
            """.strip()

            chunk = self._create_chunk(
                content=content,
                source=f"mitre_attack_{technique['id']}",
                source_type="mitre",
                metadata=technique,
            )
            self.index.add_chunk(chunk)

        # Add playbooks
        for playbook in playbooks:
            content = f"""
Incident Response Playbook: {playbook['name']}
Steps:
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(playbook['steps']))}
            """.strip()

            chunk = self._create_chunk(
                content=content,
                source=f"playbook_{playbook['name'].lower().replace(' ', '_')}",
                source_type="playbook",
                metadata=playbook,
            )
            self.index.add_chunk(chunk)

    def _create_chunk(
        self,
        content: str,
        source: str,
        source_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> DocumentChunk:
        """Create a document chunk with embedding."""
        chunk_id = hashlib.md5(content.encode()).hexdigest()[:16]
        doc_id = hashlib.md5(source.encode()).hexdigest()[:16]

        embedding = self.embedding_provider.embed_text(content)

        return DocumentChunk(
            chunk_id=chunk_id,
            document_id=doc_id,
            content=content,
            source=source,
            source_type=source_type,
            metadata=metadata or {},
            embedding=embedding,
        )

    def add_document(
        self,
        content: str,
        source: str,
        source_type: str,
        metadata: dict[str, Any] | None = None,
        chunk_size: int = 500,
    ) -> int:
        """Add a document to the knowledge base."""
        # Simple chunking by sentences/paragraphs
        chunks_added = 0
        paragraphs = content.split("\n\n")

        current_chunk = ""
        for para in paragraphs:
            if len(current_chunk) + len(para) < chunk_size:
                current_chunk += para + "\n\n"
            else:
                if current_chunk:
                    chunk = self._create_chunk(
                        content=current_chunk.strip(),
                        source=source,
                        source_type=source_type,
                        metadata=metadata,
                    )
                    self.index.add_chunk(chunk)
                    chunks_added += 1
                current_chunk = para + "\n\n"

        if current_chunk.strip():
            chunk = self._create_chunk(
                content=current_chunk.strip(),
                source=source,
                source_type=source_type,
                metadata=metadata,
            )
            self.index.add_chunk(chunk)
            chunks_added += 1

        return chunks_added

    def retrieve(self, query: RAGQuery) -> RAGResponse:
        """Retrieve relevant chunks for a query."""
        start_time = utc_now()

        # Generate query embedding
        query_embedding = self.embedding_provider.embed_text(query.query_text)

        # Search index
        search_results = self.index.search(query_embedding, query.top_k * 2)

        # Filter and rank results
        results: list[RetrievalResult] = []
        for rank, (idx, score) in enumerate(search_results):
            if score >= query.min_similarity and idx < len(self.index.chunks):
                chunk = self.index.chunks[idx]

                # Apply filters
                if query.filters:
                    if "source_type" in query.filters:
                        if chunk.source_type != query.filters["source_type"]:
                            continue

                results.append(
                    RetrievalResult(
                        chunk=chunk,
                        similarity_score=score,
                        rank=len(results) + 1,
                    )
                )

                if len(results) >= query.top_k:
                    break

        # Build context
        context_parts = []
        for r in results:
            context_parts.append(
                f"[Source: {r.chunk.source}, Score: {r.similarity_score:.2f}]\n"
                f"{r.chunk.content}"
            )
        context = "\n\n---\n\n".join(context_parts)

        end_time = utc_now()
        retrieval_time = (end_time - start_time).total_seconds() * 1000

        return RAGResponse(
            query=query.query_text,
            results=results,
            context=context,
            total_chunks_searched=self.index.size,
            retrieval_time_ms=retrieval_time,
        )

    def query(self, query_text: str, top_k: int = 5) -> RAGResponse:
        """Simple query interface."""
        return self.retrieve(RAGQuery(query_text=query_text, top_k=top_k))

    def save(self) -> None:
        """Save index to disk."""
        self.index.save(self.index_path)

    @property
    def size(self) -> int:
        """Number of chunks in knowledge base."""
        return self.index.size


# Singleton instance
_rag_instance: CybersecurityRAG | None = None


def get_rag_system() -> CybersecurityRAG:
    """Get RAG system singleton."""
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = CybersecurityRAG()
        _rag_instance.initialize()
    return _rag_instance

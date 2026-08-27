import { 
  EmbeddingRecord, 
  KnowledgeChunk,
  VectorSearchQuery, 
  VectorSearchResult 
} from '../types.ts';
import { SecurityClassificationRank } from '../../../packages/auth/src/types.ts';

export function computeCosineSimilarity(vecA: number[], vecB: number[]): number {
  if (!vecA.length || !vecB.length || vecA.length !== vecB.length) return 0;
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < vecA.length; i++) {
    dotProduct += vecA[i] * vecB[i];
    normA += vecA[i] * vecA[i];
    normB += vecB[i] * vecB[i];
  }

  const denominator = Math.sqrt(normA) * Math.sqrt(normB);
  if (denominator === 0) return 0;
  return Math.max(-1, Math.min(1, dotProduct / denominator));
}

export class PgVectorRepository {
  private embeddings: Map<string, EmbeddingRecord> = new Map();
  private chunks: Map<string, KnowledgeChunk> = new Map();

  public upsertEmbedding(embedding: EmbeddingRecord, chunk?: KnowledgeChunk): void {
    this.embeddings.set(embedding.embedding_id, embedding);
    if (chunk) {
      this.chunks.set(chunk.knowledge_chunk_id, chunk);
    }
  }

  public upsertBatch(embeddings: EmbeddingRecord[], chunks: KnowledgeChunk[] = []): void {
    embeddings.forEach((e) => this.embeddings.set(e.embedding_id, e));
    chunks.forEach((c) => this.chunks.set(c.knowledge_chunk_id, c));
  }

  public getEmbedding(embeddingId: string): EmbeddingRecord | undefined {
    return this.embeddings.get(embeddingId);
  }

  public getAllEmbeddings(): EmbeddingRecord[] {
    return Array.from(this.embeddings.values());
  }

  public deleteByChunkId(chunkId: string): boolean {
    const emb = Array.from(this.embeddings.values()).find((e) => e.knowledge_chunk_id === chunkId);
    if (emb) {
      this.embeddings.delete(emb.embedding_id);
    }
    this.chunks.delete(chunkId);
    return true;
  }

  public deleteByObjectId(knowledgeObjectId: string): number {
    let deletedCount = 0;
    for (const [id, emb] of this.embeddings.entries()) {
      if (emb.knowledge_object_id === knowledgeObjectId) {
        this.embeddings.delete(id);
        this.chunks.delete(emb.knowledge_chunk_id);
        deletedCount++;
      }
    }
    return deletedCount;
  }

  public clearAll(): void {
    this.embeddings.clear;
    this.chunks.clear();
    this.embeddings.clear();
  }

  /**
   * Performs vector similarity search with security classification filtering,
   * tenant/scope constraints, and hybrid keyword boosting.
   */
  public search(query: VectorSearchQuery): VectorSearchResult[] {
    const {
      query_vector,
      top_k = 10,
      min_similarity = 0.0,
      agent_id,
      agent_version_id,
      object_types,
      max_security_rank = SecurityClassificationRank.PUBLIC_METADATA,
      allow_vault_restricted = false,
      exact_filters = {},
      hybrid_keyword_boost = 0.25,
    } = query;

    if (!query_vector || query_vector.length === 0) {
      return [];
    }

    const candidateResults: VectorSearchResult[] = [];

    for (const emb of this.embeddings.values()) {
      // 1. Security Classification RLS check
      if (emb.security_classification_rank > max_security_rank) {
        continue;
      }

      // 2. Strict Vault Boundary check: Never return vault restricted items to non-vault callers
      if (emb.vault_restricted && !allow_vault_restricted) {
        continue;
      }

      // 3. Agent & Version Scope Filter
      if (agent_id && emb.agent_id && emb.agent_id !== agent_id) {
        continue;
      }
      if (agent_version_id && emb.agent_version_id && emb.agent_version_id !== agent_version_id) {
        continue;
      }

      // 4. Object Type Filter
      const chunk = this.chunks.get(emb.knowledge_chunk_id);
      const objectType = (emb.exact_keywords?.object_type || chunk?.exact_keywords?.object_type) as any;
      if (object_types && object_types.length > 0 && objectType && !object_types.includes(objectType)) {
        continue;
      }

      // 5. Exact Keyword Filters
      let matchesExact = true;
      for (const [key, value] of Object.entries(exact_filters)) {
        if (emb.exact_keywords && emb.exact_keywords[key] !== undefined) {
          const embVal = emb.exact_keywords[key];
          if (Array.isArray(embVal)) {
            if (!embVal.includes(value)) {
              matchesExact = false;
              break;
            }
          } else if (embVal !== value) {
            matchesExact = false;
            break;
          }
        }
      }
      if (!matchesExact) {
        continue;
      }

      // 6. Vector Similarity Calculation
      const similarity = computeCosineSimilarity(query_vector, emb.vector);
      if (similarity < min_similarity) {
        continue;
      }

      // 7. Calculate Hybrid Score with Keyword Boost
      let keywordMatches = 0;
      if (query.query_text) {
        const queryTerms = query.query_text.toLowerCase().split(/\s+/).filter(Boolean);
        const chunkText = chunk?.text_content.toLowerCase() || '';
        for (const term of queryTerms) {
          if (chunkText.includes(term)) {
            keywordMatches++;
          }
        }
      }

      const keywordRatio = Math.min(1.0, keywordMatches / 3);
      const hybridScore = (similarity * (1.0 - hybrid_keyword_boost)) + (keywordRatio * hybrid_keyword_boost);

      candidateResults.push({
        chunk_id: emb.knowledge_chunk_id,
        knowledge_object_id: emb.knowledge_object_id,
        knowledge_projection_id: chunk?.knowledge_projection_id || '',
        similarity_score: Number(similarity.toFixed(4)),
        hybrid_score: Number(hybridScore.toFixed(4)),
        text_snippet: chunk?.text_content.substring(0, 300) || '',
        object_type: objectType || 'agent',
        agent_id: emb.agent_id,
        agent_version_id: emb.agent_version_id,
        security_classification: emb.security_classification,
        vault_restricted: emb.vault_restricted,
        exact_keywords: emb.exact_keywords,
      });
    }

    // Sort by hybrid score descending
    candidateResults.sort((a, b) => b.hybrid_score - a.hybrid_score);

    return candidateResults.slice(0, top_k);
  }

  public getStats() {
    const total = this.embeddings.size;
    const byClassification: Record<string, number> = {};
    let vaultCount = 0;

    for (const emb of this.embeddings.values()) {
      byClassification[emb.security_classification] = (byClassification[emb.security_classification] || 0) + 1;
      if (emb.vault_restricted) vaultCount++;
    }

    return {
      total_embeddings: total,
      total_chunks: this.chunks.size,
      by_classification: byClassification,
      vault_restricted_count: vaultCount,
    };
  }
}

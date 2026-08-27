import crypto from 'crypto';
import { 
  EmbeddingProvider, 
  EmbeddingOptions, 
  EmbeddingResult 
} from '../types.ts';
import { GoogleGenAI } from '@google/genai';

export const GEMINI_EMBEDDING_MODEL = 'gemini-embedding-2-preview';
export const DEFAULT_EMBEDDING_DIMENSIONS = 768;

/**
 * Deterministic semantic hashing fallback when API keys are absent or running in offline test mode.
 */
export function generateDeterministicVector(text: string, dimensions: number = DEFAULT_EMBEDDING_DIMENSIONS): number[] {
  const words = text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(Boolean);
  const vector = new Array(dimensions).fill(0);

  if (words.length === 0) {
    vector[0] = 1.0;
    return vector;
  }

  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const hash = crypto.createHash('sha256').update(word).digest();
    
    // Distribute hash bytes into dimensions
    for (let b = 0; b < hash.length; b += 2) {
      const idx = (hash[b] * 256 + hash[b + 1]) % dimensions;
      const weight = ((hash[b % 16] - 128) / 128) * (1 / Math.sqrt(i + 1));
      vector[idx] += weight;
    }
  }

  // Normalize vector to unit length (L2 norm)
  let normSq = 0;
  for (let d = 0; d < dimensions; d++) {
    normSq += vector[d] * vector[d];
  }
  const norm = Math.sqrt(normSq) || 1.0;
  for (let d = 0; d < dimensions; d++) {
    vector[d] = Number((vector[d] / norm).toFixed(6));
  }

  return vector;
}

/**
 * Gemini Embedding Provider implementing Google GenAI SDK.
 */
export class GeminiEmbeddingProvider implements EmbeddingProvider {
  public readonly modelName: string;
  public readonly dimensions: number;
  private client: GoogleGenAI | null = null;

  constructor(apiKey?: string, modelName: string = GEMINI_EMBEDDING_MODEL, dimensions: number = DEFAULT_EMBEDDING_DIMENSIONS) {
    this.modelName = modelName;
    this.dimensions = dimensions;
    const key = apiKey || process.env.GEMINI_API_KEY;
    if (key) {
      this.client = new GoogleGenAI({ apiKey: key });
    }
  }

  public async generateEmbedding(text: string, options: EmbeddingOptions = {}): Promise<EmbeddingResult> {
    const results = await this.generateEmbeddings([text], options);
    return results[0];
  }

  public async generateEmbeddings(texts: string[], options: EmbeddingOptions = {}): Promise<EmbeddingResult[]> {
    if (!texts.length) return [];

    const dim = options.outputDimensionality || this.dimensions;

    // Use Gemini client if available and configured
    if (this.client && process.env.GEMINI_API_KEY) {
      try {
        const results: EmbeddingResult[] = [];
        for (const text of texts) {
          // Call modern @google/genai embedding endpoint
          const response = await (this.client as any).models.embedContent({
            model: this.modelName,
            contents: text,
            config: {
              outputDimensionality: dim,
              taskType: options.taskType || 'RETRIEVAL_DOCUMENT',
            },
          });

          const values: number[] = response.embedding?.values || [];
          results.push({
            vector: values.length === dim ? values : generateDeterministicVector(text, dim),
            dimensions: dim,
            tokenCount: Math.ceil(text.length / 4),
            model: this.modelName,
          });
        }
        return results;
      } catch (err) {
        console.warn(`[GeminiEmbeddingProvider] API call fallback to deterministic vector: ${(err as Error).message}`);
      }
    }

    // Deterministic fallback for test/offline environments
    return texts.map((text) => ({
      vector: generateDeterministicVector(text, dim),
      dimensions: dim,
      tokenCount: Math.ceil(text.length / 4),
      model: `${this.modelName}-fallback`,
    }));
  }
}

/**
 * Explicit Deterministic Provider for unit testing.
 */
export class DeterministicMockEmbeddingProvider implements EmbeddingProvider {
  public readonly modelName = 'mock-gemini-emb-v1';
  public readonly dimensions: number;

  constructor(dimensions: number = DEFAULT_EMBEDDING_DIMENSIONS) {
    this.dimensions = dimensions;
  }

  public async generateEmbedding(text: string, options: EmbeddingOptions = {}): Promise<EmbeddingResult> {
    const dim = options.outputDimensionality || this.dimensions;
    return {
      vector: generateDeterministicVector(text, dim),
      dimensions: dim,
      tokenCount: Math.ceil(text.length / 4),
      model: this.modelName,
    };
  }

  public async generateEmbeddings(texts: string[], options: EmbeddingOptions = {}): Promise<EmbeddingResult[]> {
    return Promise.all(texts.map((t) => this.generateEmbedding(t, options)));
  }
}

import { SourceAdapter } from './types.ts';
import { SourceNotFoundError } from './errors.ts';
import { GitHubSourceAdapter, GitHubAdapterOptions } from './adapters/github.ts';
import { GitLabSourceAdapter, GitLabAdapterOptions } from './adapters/gitlab.ts';
import { PyPISourceAdapter, PyPIAdapterOptions } from './adapters/pypi.ts';
import { NpmSourceAdapter, NpmAdapterOptions } from './adapters/npm.ts';
import { HuggingFaceSourceAdapter, HuggingFaceAdapterOptions } from './adapters/huggingface.ts';
import { DockerHubSourceAdapter, DockerHubAdapterOptions } from './adapters/dockerhub.ts';
import { CodebergSourceAdapter, CodebergAdapterOptions } from './adapters/codeberg.ts';

export interface DefaultRegistryOptions {
  github?: GitHubAdapterOptions;
  gitlab?: GitLabAdapterOptions;
  pypi?: PyPIAdapterOptions;
  npm?: NpmAdapterOptions;
  huggingface?: HuggingFaceAdapterOptions;
  dockerhub?: DockerHubAdapterOptions;
  codeberg?: CodebergAdapterOptions;
}

export class SourceAdapterRegistry {
  private adapters = new Map<string, SourceAdapter>();

  register(adapter: SourceAdapter): this {
    this.adapters.set(adapter.sourceType.toLowerCase(), adapter);
    return this;
  }

  unregister(sourceType: string): boolean {
    return this.adapters.delete(sourceType.toLowerCase());
  }

  get(sourceType: string): SourceAdapter | undefined {
    return this.adapters.get(sourceType.toLowerCase());
  }

  mustGet(sourceType: string): SourceAdapter {
    const adapter = this.get(sourceType);
    if (!adapter) {
      throw new SourceNotFoundError(`No source adapter registered for type: '${sourceType}'`, {
        sourceType,
        locator: `source://${sourceType}`,
      });
    }
    return adapter;
  }

  getAll(): SourceAdapter[] {
    return Array.from(this.adapters.values());
  }

  /**
   * Automatically resolves which adapter handles a given locator string based on protocol or domain.
   */
  resolveForLocator(locator: string): SourceAdapter {
    const clean = locator.toLowerCase();

    if (clean.startsWith('github://') || clean.includes('github.com')) {
      return this.mustGet('github');
    }
    if (clean.startsWith('gitlab://') || clean.includes('gitlab.com')) {
      return this.mustGet('gitlab');
    }
    if (clean.startsWith('pypi://') || clean.includes('pypi.org')) {
      return this.mustGet('pypi');
    }
    if (clean.startsWith('npm://') || clean.includes('npmjs.com') || clean.includes('registry.npmjs.org')) {
      return this.mustGet('npm');
    }
    if (clean.startsWith('hf://') || clean.includes('huggingface.co')) {
      return this.mustGet('huggingface');
    }
    if (clean.startsWith('docker://') || clean.includes('docker.io') || clean.includes('hub.docker.com')) {
      return this.mustGet('dockerhub');
    }
    if (clean.startsWith('codeberg://') || clean.includes('codeberg.org')) {
      return this.mustGet('codeberg');
    }

    // Try matching any registered adapter by prefix
    for (const adapter of this.adapters.values()) {
      if (clean.startsWith(`${adapter.sourceType}://`)) {
        return adapter;
      }
    }

    throw new SourceNotFoundError(`Unable to infer source adapter for locator: '${locator}'`, {
      sourceType: 'unknown',
      locator,
    });
  }

  /**
   * Creates a registry pre-populated with all 7 standard adapters.
   */
  static createDefault(options: DefaultRegistryOptions = {}): SourceAdapterRegistry {
    const registry = new SourceAdapterRegistry();
    registry.register(new GitHubSourceAdapter(options.github));
    registry.register(new GitLabSourceAdapter(options.gitlab));
    registry.register(new PyPISourceAdapter(options.pypi));
    registry.register(new NpmSourceAdapter(options.npm));
    registry.register(new HuggingFaceSourceAdapter(options.huggingface));
    registry.register(new DockerHubSourceAdapter(options.dockerhub));
    registry.register(new CodebergSourceAdapter(options.codeberg));
    return registry;
  }
}

# get_env_vars

A CLI tool to extract and classify environment variables from Kubernetes pods or Docker containers. It automatically categorizes secrets and generates vault-ready output files.

## Features

- Extract environment variables from **Kubernetes pods** or **Docker containers**
- Automatic classification of variables (passwords, usernames, URLs, database configs, etc.)
- Multiple output formats:
  - Raw environment variables
  - Classified/organized output
  - HashiCorp Vault JSON format
  - Shell export scripts
- Namespace filtering and exclusion
- Consolidated or per-pod output modes
- Colored terminal output

## Requirements

- Python 3.6+
- `kubectl` (for Kubernetes mode)
- `docker` (for Docker mode)

## Installation

Clone the repository and run directly:

```bash
git clone <repo-url>
cd get_env_vars
python get_env_vars.py --help
```

## Usage

### Kubernetes Mode (default)

Extract from all namespaces:
```bash
python get_env_vars.py -v
```

Extract from specific namespaces:
```bash
python get_env_vars.py -n default production -v
```

Exclude system namespaces:
```bash
python get_env_vars.py -x kube-system kube-public -v
```

Use a specific kubeconfig and context:
```bash
python get_env_vars.py -k ~/.kube/config -c my-cluster -v
```

### Docker Mode

Extract from all running Docker containers:
```bash
python get_env_vars.py -d -v
```

### Output Options

Generate consolidated output (one file per namespace instead of per-pod):
```bash
python get_env_vars.py --consolidated -v
```

Generate shell-style export files:
```bash
python get_env_vars.py --shell-export -v
```

Specify custom output directory:
```bash
python get_env_vars.py -o ./my_output -v
```

Test mode (auto-increments output folder name):
```bash
python get_env_vars.py --test -v
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-k, --kubeconfig` | Path to kubeconfig file |
| `-c, --context` | Kubernetes context to use |
| `-n, --namespace` | Target namespaces (space-separated) |
| `-x, --exclude-namespace` | Namespaces to exclude |
| `-o, --output` | Output directory (default: `env_vars_output`) |
| `--consolidated` | One file per namespace instead of per-pod |
| `-v, --verbose` | Increase verbosity (`-v` for INFO, `-vv` for DEBUG) |
| `-q, --quiet` | Suppress output except errors |
| `--no-color` | Disable colored output |
| `--test` | Auto-increment output folder name |
| `--shell-export` | Generate shell-style export files |
| `-d, --docker` | Use Docker containers instead of Kubernetes |

## Classification Categories

Environment variables are automatically classified into:

| Category | Examples |
|----------|----------|
| `password` | `*_PASSWORD`, `*_SECRET`, `*_TOKEN`, `*_API_KEY` |
| `username` | `*_USER`, `*_USERNAME`, `*_LOGIN`, `*_CLIENT_ID` |
| `internal_url` | URLs pointing to private IPs, `.local`, `.internal` |
| `external_url` | Public URLs, webhooks, callbacks |
| `database` | `*_DATABASE`, `*_DB_NAME`, connection strings |
| `port` | Variables ending in `_PORT` with numeric values |
| `email` | Email addresses |
| `other` | Unclassified variables |

## Output Files

### Per-Pod Mode (default)

```
env_vars_output/
├── namespace1/
│   ├── pod1_env_raw.txt
│   ├── pod1_env_classified.txt
│   ├── pod1_vault_candidates.txt
│   └── ...
├── VAULT_SUMMARY.txt
├── vault_hashicorp.json
├── vault_flat.json
├── vault_by_namespace.json
└── vault_simple_kv.json
```

### Consolidated Mode

```
env_vars_output/
├── namespace1/
│   ├── namespace1_consolidated.json
│   └── namespace1_consolidated.txt
├── VAULT_SUMMARY.txt
└── vault_*.json
```

### With Shell Exports

```
env_vars_output/
├── namespace1/
│   ├── namespace1_shell_exports.sh
│   ├── namespace1_high_confidence.sh
│   ├── namespace1_medium_confidence.sh
│   └── namespace1_low_confidence.sh
├── ALL_SHELL_EXPORTS.sh
└── ...
```

## Examples

Full extraction with all features:
```bash
python get_env_vars.py \
  -n production staging \
  -x kube-system \
  --consolidated \
  --shell-export \
  -o ./secrets_export \
  -vv
```

Quick Docker scan:
```bash
python get_env_vars.py -d --shell-export -v
```

## Security Notes

- Sensitive values are masked in log output
- Raw values are written to output files - handle with care
- Vault candidate files highlight secrets that should be stored securely
- Consider encrypting or securing the output directory after extraction

## License

MIT

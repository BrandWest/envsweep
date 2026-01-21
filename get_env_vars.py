import subprocess
import os
import argparse
import logging
import re
import json
import sys
from datetime import datetime

# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""
        cls.BRIGHT_RED = ""
        cls.BRIGHT_GREEN = ""
        cls.BRIGHT_YELLOW = ""
        cls.BRIGHT_BLUE = ""
        cls.BRIGHT_MAGENTA = ""
        cls.BRIGHT_CYAN = ""


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors based on log level."""

    def __init__(self, fmt=None, datefmt=None):
        super().__init__(fmt, datefmt)
        self.level_colors = {
            logging.DEBUG: Colors.DIM,
            logging.INFO: Colors.RESET,
            logging.WARNING: Colors.YELLOW,
            logging.ERROR: Colors.BRIGHT_RED,
            logging.CRITICAL: Colors.BOLD + Colors.BRIGHT_RED,
        }

    def format(self, record):
        # Color the level name
        level_color = self.level_colors.get(record.levelno, Colors.RESET)
        record.levelname = f"{level_color}{record.levelname}{Colors.RESET}"

        # Format the message
        formatted = super().format(record)
        return formatted


def colorize(text, color):
    """Wrap text in color codes."""
    return f"{color}{text}{Colors.RESET}"


def highlight_pod(pod_name):
    """Highlight a pod name."""
    return colorize(pod_name, Colors.BRIGHT_CYAN + Colors.BOLD)


def highlight_container(container_name):
    """Highlight a container name."""
    return colorize(container_name, Colors.BRIGHT_CYAN + Colors.BOLD)


def highlight_namespace(ns_name):
    """Highlight a namespace name."""
    return colorize(ns_name, Colors.BRIGHT_MAGENTA + Colors.BOLD)


def highlight_classification(cls_name):
    """Highlight a classification type."""
    cls_colors = {
        "password": Colors.BRIGHT_RED,
        "username": Colors.BRIGHT_YELLOW,
        "internal_url": Colors.BRIGHT_BLUE,
        "external_url": Colors.BRIGHT_GREEN,
        "database": Colors.BRIGHT_MAGENTA,
        "email": Colors.CYAN,
        "port": Colors.DIM,
        "other": Colors.DIM,
    }
    color = cls_colors.get(cls_name, Colors.RESET)
    return colorize(cls_name, color)


def highlight_count(count):
    """Highlight a count/number."""
    return colorize(str(count), Colors.BRIGHT_GREEN + Colors.BOLD)


def highlight_path(path):
    """Highlight a file path."""
    return colorize(path, Colors.BRIGHT_BLUE)


def highlight_success(text):
    """Highlight success messages."""
    return colorize(text, Colors.BRIGHT_GREEN)


def highlight_warning(text):
    """Highlight warning text."""
    return colorize(text, Colors.YELLOW)


def highlight_error(text):
    """Highlight error text."""
    return colorize(text, Colors.BRIGHT_RED)


logger = logging.getLogger(__name__)

# Classification patterns for environment variables
CLASSIFICATION_PATTERNS = {
    "password": {
        "key_patterns": [
            r"pass(word)?", r"pwd", r"secret", r"token", r"api_?key",
            r"auth_?key", r"private_?key", r"credential", r"client_?secret"
        ],
        "priority": 1,
    },
    "username": {
        "key_patterns": [
            r"user(name)?", r"login", r"account", r"admin_?user",
            r"db_?user", r"service_?account", r"client_?id"
        ],
        "priority": 2,
    },
    "internal_url": {
        "key_patterns": [
            r"(internal|private|local)_?(url|host|endpoint|uri)",
            r"db_?(host|url|uri)", r"redis_?(host|url)", r"kafka_?(host|url)",
            r"mongodb_?(host|url)", r"postgres_?(host|url)", r"mysql_?(host|url)"
        ],
        "value_patterns": [
            r"^https?://10\.", r"^https?://192\.168\.", r"^https?://172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^https?://localhost", r"^https?://127\.", r"\.local(:\d+)?(/|$)",
            r"\.internal(:\d+)?(/|$)", r"\.svc\.cluster\.local"
        ],
        "priority": 3,
    },
    "external_url": {
        "key_patterns": [
            r"(external|public|api|base)_?(url|host|endpoint|uri)",
            r"webhook_?url", r"callback_?url", r"homepage"
        ],
        "value_patterns": [
            r"^https?://(?!10\.)(?!192\.168\.)(?!172\.(1[6-9]|2[0-9]|3[0-1])\.)(?!localhost)(?!127\.)"
        ],
        "priority": 4,
    },
    "database": {
        "key_patterns": [
            r"db_?(name|database)", r"database", r"schema",
            r"connection_?string", r"dsn"
        ],
        "priority": 5,
    },
    "port": {
        "key_patterns": [r"_?port$"],
        "value_patterns": [r"^\d{2,5}$"],
        "priority": 6,
    },
    "email": {
        "key_patterns": [r"email", r"mail", r"smtp_?(from|to|user)"],
        "value_patterns": [r"^[^@]+@[^@]+\.[^@]+$"],
        "priority": 7,
    },
}


def classify_env_var(key, value):
    """
    Classify an environment variable based on its key and value.
    Returns a tuple of (classification, confidence).
    """
    key_lower = key.lower()
    value_lower = value.lower() if value else ""

    for classification, patterns in CLASSIFICATION_PATTERNS.items():
        # Check key patterns
        key_match = False
        for pattern in patterns.get("key_patterns", []):
            if re.search(pattern, key_lower):
                key_match = True
                break

        # Check value patterns
        value_match = False
        for pattern in patterns.get("value_patterns", []):
            if re.search(pattern, value_lower) or re.search(pattern, value):
                value_match = True
                break

        # Determine confidence based on matches
        if key_match and value_match:
            return classification, "high"
        elif key_match:
            return classification, "medium"
        elif value_match:
            return classification, "low"

    return "other", "none"


def parse_env_vars(env_output):
    """Parse environment variable output into a list of (key, value, classification, confidence) tuples."""
    results = []
    if not env_output:
        return results

    for line in env_output.strip().split("\n"):
        if "=" in line:
            key, _, value = line.partition("=")
            classification, confidence = classify_env_var(key, value)
            results.append({
                "key": key,
                "value": value,
                "classification": classification,
                "confidence": confidence
            })

    return results


def mask_secret(value, classification):
    """Mask sensitive values for logging purposes."""
    sensitive_types = ["password", "username", "email"]

    if classification in sensitive_types:
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return value


def get_masked_summary(classified_items):
    """Get a summary of classified items with sensitive values masked."""
    summary = []
    for item in classified_items:
        masked_value = mask_secret(item["value"], item["classification"])
        summary.append(f"{item['key']}={masked_value} [{item['classification']}]")
    return summary


def setup_logging(level, no_color=False):
    """Configure logging with the specified level and optional colors."""
    # Disable colors if not a TTY or explicitly disabled
    if no_color or not sys.stdout.isatty():
        Colors.disable()

    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Create handler with colored formatter
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter(log_format, date_format))

    # Configure root logger
    logging.root.handlers = []
    logging.root.addHandler(handler)
    logging.root.setLevel(level)


def get_args():
    parser = argparse.ArgumentParser(
        description="Extract environment variables from Kubernetes pods"
    )
    parser.add_argument(
        "-k", "--kubeconfig",
        help="Path to kubeconfig file. If not specified, uses default kubectl config."
    )
    parser.add_argument(
        "-c", "--context",
        help="Kubernetes context to use."
    )
    parser.add_argument(
        "-n", "--namespace",
        nargs='*',
        help="Optional list of namespaces to target. If not specified, gets all namespaces."
    )
    parser.add_argument(
        "-x", "--exclude-namespace",
        nargs='*',
        default=[],
        help="List of namespaces to exclude (e.g., -x kube-system kube-public)"
    )
    parser.add_argument(
        "-o", "--output",
        default="env_vars_output",
        help="Output directory for environment variable files (default: env_vars_output)"
    )
    parser.add_argument(
        "--consolidated",
        action="store_true",
        help="Output one consolidated file per namespace instead of separate files per pod"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output except errors"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test mode: auto-increment output folder name (env_vars_output1, env_vars_output2, etc.)"
    )
    parser.add_argument(
        "--shell-export",
        action="store_true",
        help="Generate shell-style export files organized by namespace and confidence level"
    )
    parser.add_argument(
        "-d", "--docker",
        action="store_true",
        help="Extract environment variables from Docker containers instead of Kubernetes pods"
    )
    return parser.parse_args()


def get_next_test_output_dir(base_dir):
    """Get the next available test output directory with incremented counter."""
    counter = 1
    while True:
        test_dir = f"{base_dir}{counter}"
        if not os.path.exists(test_dir):
            return test_dir
        counter += 1


def run_kubectl(cmd, kubeconfig=None, context=None):
    """Run a kubectl command and return the output."""
    full_cmd = ["kubectl"]
    if kubeconfig:
        full_cmd.extend(["--kubeconfig", kubeconfig])
    if context:
        full_cmd.extend(["--context", context])
    full_cmd.extend(cmd)

    logger.debug(f"Running command: {' '.join(full_cmd)}")
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"kubectl command failed: {result.stderr.strip()}")
        return None
    logger.debug(f"Command output: {result.stdout[:200]}..." if len(result.stdout) > 200 else f"Command output: {result.stdout}")
    return result.stdout


def get_namespaces(kubeconfig=None, context=None):
    """Get all namespaces from the cluster."""
    output = run_kubectl(
        ["get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}"],
        kubeconfig, context
    )
    if output:
        return output.split()
    return []


def get_pods(namespace, kubeconfig=None, context=None):
    """Get all pods in a namespace."""
    output = run_kubectl(
        ["get", "pods", "-n", namespace, "-o", "jsonpath={.items[*].metadata.name}"],
        kubeconfig, context
    )
    if output:
        return output.split()
    return []


def get_pod_env_vars(namespace, pod, kubeconfig=None, context=None):
    """Execute into a pod and get environment variables."""
    output = run_kubectl(
        ["exec", "-n", namespace, pod, "--", "env"],
        kubeconfig, context
    )
    return output


# Docker functions
def run_docker(cmd):
    """Run a docker command and return the output."""
    full_cmd = ["docker"] + cmd

    logger.debug(f"Running command: {' '.join(full_cmd)}")
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"docker command failed: {result.stderr.strip()}")
        return None
    logger.debug(f"Command output: {result.stdout[:200]}..." if len(result.stdout) > 200 else f"Command output: {result.stdout}")
    return result.stdout


def get_docker_containers():
    """Get all containers from docker ps -a (returns list of dicts with id, name, status)."""
    # Use format to get container ID, name, and status
    output = run_docker(["ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}"])
    if not output:
        return []

    containers = []
    for line in output.strip().split("\n"):
        if line:
            parts = line.split("\t")
            if len(parts) >= 3:
                containers.append({
                    "id": parts[0],
                    "name": parts[1],
                    "status": parts[2]
                })
    return containers


def get_container_env_vars(container_id):
    """Execute into a container and get environment variables."""
    output = run_docker(["exec", container_id, "env"])
    return output


def classify_pod_env_vars(env_vars):
    """Parse and classify environment variables for a pod."""
    return parse_env_vars(env_vars)


def save_env_vars(output_dir, namespace, pod, env_vars):
    """Save environment variables to files, organized by classification (per-pod files)."""
    ns_dir = os.path.join(output_dir, namespace)
    os.makedirs(ns_dir, exist_ok=True)

    # Parse and classify env vars
    classified = parse_env_vars(env_vars)

    # Save raw env vars
    raw_filepath = os.path.join(ns_dir, f"{pod}_env_raw.txt")
    with open(raw_filepath, 'w') as f:
        f.write(f"# Environment variables for pod: {pod}\n")
        f.write(f"# Namespace: {namespace}\n")
        f.write(f"# Extracted at: {datetime.now().isoformat()}\n\n")
        f.write(env_vars)
    logger.debug(f"Saved raw: {raw_filepath}")

    # Save classified env vars
    classified_filepath = os.path.join(ns_dir, f"{pod}_env_classified.txt")
    with open(classified_filepath, 'w') as f:
        f.write(f"# Classified environment variables for pod: {pod}\n")
        f.write(f"# Namespace: {namespace}\n")
        f.write(f"# Extracted at: {datetime.now().isoformat()}\n")
        f.write(f"# Classifications: password, username, internal_url, external_url, database, port, email, other\n\n")

        # Group by classification
        by_classification = {}
        for item in classified:
            cls = item["classification"]
            if cls not in by_classification:
                by_classification[cls] = []
            by_classification[cls].append(item)

        # Output in priority order
        priority_order = ["password", "username", "internal_url", "external_url", "database", "port", "email", "other"]
        for cls in priority_order:
            if cls in by_classification:
                f.write(f"\n{'='*60}\n")
                f.write(f"[{cls.upper()}]\n")
                f.write(f"{'='*60}\n")
                for item in by_classification[cls]:
                    confidence_marker = f" ({item['confidence']})" if item['confidence'] != "none" else ""
                    f.write(f"{item['key']}={item['value']}{confidence_marker}\n")

    logger.info(f"Saved classified: {highlight_path(classified_filepath)}")

    # Generate vault-ready summary of important values
    vault_filepath = os.path.join(ns_dir, f"{pod}_vault_candidates.txt")
    vault_categories = ["password", "username", "internal_url", "external_url", "database", "email"]
    has_vault_items = any(cls in by_classification for cls in vault_categories)

    if has_vault_items:
        with open(vault_filepath, 'w') as f:
            f.write(f"# Vault candidates for pod: {pod}\n")
            f.write(f"# Namespace: {namespace}\n")
            f.write(f"# These are likely values you want to store in your vault\n")
            f.write(f"# Extracted at: {datetime.now().isoformat()}\n\n")

            for cls in vault_categories:
                if cls in by_classification:
                    f.write(f"\n## {cls.upper()}\n")
                    for item in by_classification[cls]:
                        f.write(f"# Key: {item['key']}\n")
                        f.write(f"# Confidence: {item['confidence']}\n")
                        f.write(f"{item['key']}={item['value']}\n\n")

        logger.info(f"Saved vault candidates: {highlight_path(vault_filepath)}")

    return classified


def save_namespace_consolidated(output_dir, namespace, pods_data):
    """
    Save consolidated output for a namespace - one file with all pods.

    pods_data: list of (pod_name, classified_env_vars) tuples
    """
    ns_dir = os.path.join(output_dir, namespace)
    os.makedirs(ns_dir, exist_ok=True)

    timestamp = datetime.now().isoformat()
    vault_categories = ["password", "username", "internal_url", "external_url", "database", "email"]

    # Build consolidated data structure
    consolidated = {
        "namespace": namespace,
        "generated_at": timestamp,
        "pods": {}
    }

    for pod_name, classified in pods_data:
        pod_data = {
            "all_vars": [],
            "by_classification": {},
            "vault_candidates": []
        }

        for item in classified:
            # Add to all vars
            pod_data["all_vars"].append({
                "key": item["key"],
                "value": item["value"]
            })

            # Group by classification
            cls = item["classification"]
            if cls not in pod_data["by_classification"]:
                pod_data["by_classification"][cls] = []
            pod_data["by_classification"][cls].append({
                "key": item["key"],
                "value": item["value"],
                "confidence": item["confidence"]
            })

            # Add to vault candidates if applicable
            if cls in vault_categories:
                pod_data["vault_candidates"].append({
                    "key": item["key"],
                    "value": item["value"],
                    "classification": cls,
                    "confidence": item["confidence"]
                })

        consolidated["pods"][pod_name] = pod_data

    # Save consolidated JSON
    json_filepath = os.path.join(ns_dir, f"{namespace}_consolidated.json")
    with open(json_filepath, 'w') as f:
        json.dump(consolidated, f, indent=2)
    logger.info(f"Saved consolidated JSON: {highlight_path(json_filepath)}")

    # Save human-readable text file
    txt_filepath = os.path.join(ns_dir, f"{namespace}_consolidated.txt")
    with open(txt_filepath, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write(f"NAMESPACE: {namespace}\n")
        f.write(f"Generated at: {timestamp}\n")
        f.write(f"Total pods: {len(pods_data)}\n")
        f.write("=" * 70 + "\n\n")

        for pod_name, classified in pods_data:
            f.write("\n" + "=" * 70 + "\n")
            f.write(f"POD: {pod_name}\n")
            f.write("=" * 70 + "\n")

            # Group by classification for this pod
            by_cls = {}
            for item in classified:
                cls = item["classification"]
                if cls not in by_cls:
                    by_cls[cls] = []
                by_cls[cls].append(item)

            priority_order = ["password", "username", "internal_url", "external_url", "database", "port", "email", "other"]
            for cls in priority_order:
                if cls in by_cls:
                    f.write(f"\n  [{cls.upper()}]\n")
                    f.write("  " + "-" * 40 + "\n")
                    for item in by_cls[cls]:
                        confidence_marker = f" ({item['confidence']})" if item['confidence'] != "none" else ""
                        f.write(f"  {item['key']}={item['value']}{confidence_marker}\n")

    logger.info(f"Saved consolidated text: {highlight_path(txt_filepath)}")

    return consolidated


def generate_summary_report(output_dir, all_classified, mask_in_logs=True):
    """Generate a summary report of all vault candidates across all pods."""
    summary_filepath = os.path.join(output_dir, "VAULT_SUMMARY.txt")

    # Aggregate by classification
    summary = {
        "password": [],
        "username": [],
        "internal_url": [],
        "external_url": [],
        "database": [],
        "email": [],
    }

    for ns, pod, classified in all_classified:
        for item in classified:
            cls = item["classification"]
            if cls in summary:
                summary[cls].append({
                    "namespace": ns,
                    "pod": pod,
                    "key": item["key"],
                    "value": item["value"],
                    "confidence": item["confidence"]
                })

    with open(summary_filepath, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("VAULT CANDIDATES SUMMARY\n")
        f.write(f"Generated at: {datetime.now().isoformat()}\n")
        f.write("=" * 70 + "\n\n")

        total_items = sum(len(items) for items in summary.values())
        f.write(f"Total vault candidates found: {total_items}\n\n")

        for cls, items in summary.items():
            if items:
                f.write(f"\n{'='*70}\n")
                f.write(f"[{cls.upper()}] - {len(items)} items\n")
                f.write(f"{'='*70}\n\n")

                for item in items:
                    f.write(f"Namespace: {item['namespace']}\n")
                    f.write(f"Pod: {item['pod']}\n")
                    f.write(f"Key: {item['key']}\n")
                    f.write(f"Value: {item['value']}\n")
                    f.write(f"Confidence: {item['confidence']}\n")
                    f.write("-" * 40 + "\n")

    logger.info(f"Generated summary report: {highlight_path(summary_filepath)}")

    # Log a masked preview of found secrets
    if mask_in_logs:
        for cls, items in summary.items():
            if items:
                logger.debug(f"  [{cls}] Found {len(items)} items:")
                for item in items[:3]:  # Only show first 3 per category in logs
                    masked = mask_secret(item["value"], cls)
                    logger.debug(f"    {item['key']}={masked}")
                if len(items) > 3:
                    logger.debug(f"    ... and {len(items) - 3} more")

    return summary


def generate_vault_json(output_dir, all_classified, context=None):
    """
    Generate JSON files suitable for vault API imports.

    Creates multiple JSON formats:
    - vault_secrets.json: HashiCorp Vault KV format (path -> {data: {key: value}})
    - vault_flat.json: Flat key-value pairs with metadata
    - vault_by_namespace.json: Organized by namespace for bulk imports
    """
    vault_categories = ["password", "username", "internal_url", "external_url", "database", "email"]
    timestamp = datetime.now().isoformat()

    # Collect all vault candidates with deduplication
    seen_values = {}  # Track unique key-value pairs
    all_secrets = []

    for ns, pod, classified in all_classified:
        for item in classified:
            if item["classification"] not in vault_categories:
                continue

            # Create a unique identifier for deduplication
            dedup_key = f"{item['key']}:{item['value']}"

            if dedup_key in seen_values:
                # Add this source to existing entry
                seen_values[dedup_key]["sources"].append({
                    "namespace": ns,
                    "pod": pod
                })
            else:
                secret_entry = {
                    "key": item["key"],
                    "value": item["value"],
                    "classification": item["classification"],
                    "confidence": item["confidence"],
                    "sources": [{
                        "namespace": ns,
                        "pod": pod
                    }]
                }
                seen_values[dedup_key] = secret_entry
                all_secrets.append(secret_entry)

    # 1. HashiCorp Vault KV v2 format
    # Structure: secret/<namespace>/<classification> -> {data: {key: value, ...}}
    hashicorp_format = {
        "metadata": {
            "generated_at": timestamp,
            "context": context,
            "total_secrets": len(all_secrets),
            "format": "hashicorp_vault_kv_v2"
        },
        "secrets": {}
    }

    for secret in all_secrets:
        # Use first source's namespace for path
        ns = secret["sources"][0]["namespace"]
        cls = secret["classification"]
        path = f"secret/data/{ns}/{cls}"

        if path not in hashicorp_format["secrets"]:
            hashicorp_format["secrets"][path] = {
                "data": {},
                "metadata": {
                    "classification": cls,
                    "namespace": ns
                }
            }
        hashicorp_format["secrets"][path]["data"][secret["key"]] = secret["value"]

    hashicorp_filepath = os.path.join(output_dir, "vault_hashicorp.json")
    with open(hashicorp_filepath, 'w') as f:
        json.dump(hashicorp_format, f, indent=2)
    logger.info(f"Generated HashiCorp Vault format: {highlight_path(hashicorp_filepath)}")

    # 2. Flat format with full metadata (good for custom imports)
    flat_format = {
        "metadata": {
            "generated_at": timestamp,
            "context": context,
            "total_secrets": len(all_secrets),
            "unique_secrets": len(all_secrets),
            "format": "flat_with_metadata"
        },
        "secrets": all_secrets
    }

    flat_filepath = os.path.join(output_dir, "vault_flat.json")
    with open(flat_filepath, 'w') as f:
        json.dump(flat_format, f, indent=2)
    logger.info(f"Generated flat JSON format: {highlight_path(flat_filepath)}")

    # 3. By namespace format (for namespace-scoped vault paths)
    by_namespace = {
        "metadata": {
            "generated_at": timestamp,
            "context": context,
            "format": "by_namespace"
        },
        "namespaces": {}
    }

    for secret in all_secrets:
        for source in secret["sources"]:
            ns = source["namespace"]
            if ns not in by_namespace["namespaces"]:
                by_namespace["namespaces"][ns] = {
                    "secrets": {},
                    "by_classification": {}
                }

            # Add to flat secrets dict
            by_namespace["namespaces"][ns]["secrets"][secret["key"]] = secret["value"]

            # Add to classification groups
            cls = secret["classification"]
            if cls not in by_namespace["namespaces"][ns]["by_classification"]:
                by_namespace["namespaces"][ns]["by_classification"][cls] = {}
            by_namespace["namespaces"][ns]["by_classification"][cls][secret["key"]] = secret["value"]

    namespace_filepath = os.path.join(output_dir, "vault_by_namespace.json")
    with open(namespace_filepath, 'w') as f:
        json.dump(by_namespace, f, indent=2)
    logger.info(f"Generated namespace-organized JSON: {highlight_path(namespace_filepath)}")

    # 4. Simple key-value pairs only (minimal format for direct API calls)
    simple_kv = {}
    for secret in all_secrets:
        simple_kv[secret["key"]] = secret["value"]

    simple_filepath = os.path.join(output_dir, "vault_simple_kv.json")
    with open(simple_filepath, 'w') as f:
        json.dump(simple_kv, f, indent=2)
    logger.info(f"Generated simple KV JSON: {highlight_path(simple_filepath)}")

    return {
        "total_secrets": len(all_secrets),
        "deduplicated_from": sum(len(s["sources"]) for s in all_secrets),
        "files": [hashicorp_filepath, flat_filepath, namespace_filepath, simple_filepath]
    }


def generate_shell_exports(output_dir, all_classified):
    """
    Generate shell-style export files organized by namespace and confidence level.

    Creates files in format:
      namespace/
        namespace_shell_exports.sh
        namespace_high_confidence.sh
        namespace_medium_confidence.sh
        namespace_low_confidence.sh

    Each file contains lines like:
      db_password="dev-db-pass" \
      redis_password="dev-redis-pass" \
    """
    vault_categories = ["password", "username", "internal_url", "external_url", "database", "email"]
    timestamp = datetime.now().isoformat()

    # Organize by namespace
    by_namespace = {}
    for ns, pod, classified in all_classified:
        if ns not in by_namespace:
            by_namespace[ns] = {
                "high": [],
                "medium": [],
                "low": []
            }

        for item in classified:
            # Only include vault-relevant categories
            if item["classification"] not in vault_categories:
                continue

            confidence = item["confidence"]
            if confidence in ["high", "medium", "low"]:
                # Deduplicate within namespace by key
                existing_keys = [x["key"] for x in by_namespace[ns][confidence]]
                if item["key"] not in existing_keys:
                    by_namespace[ns][confidence].append({
                        "key": item["key"],
                        "value": item["value"],
                        "classification": item["classification"],
                        "pod": pod
                    })

    files_created = []

    for ns, confidence_groups in by_namespace.items():
        ns_dir = os.path.join(output_dir, ns)
        os.makedirs(ns_dir, exist_ok=True)

        # Helper function to format items as shell exports
        def format_shell_exports(items, include_comments=True):
            """Format items as shell-style variable assignments."""
            if not items:
                return ""

            lines = []
            for i, item in enumerate(items):
                # Escape special characters in value
                value = item["value"].replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")

                if include_comments:
                    lines.append(f"  # [{item['classification']}] from pod: {item['pod']}")

                # Add trailing backslash except for the last item
                if i < len(items) - 1:
                    lines.append(f'  {item["key"]}="{value}" \\')
                else:
                    lines.append(f'  {item["key"]}="{value}"')

            return "\n".join(lines)

        # 1. Generate combined file with all confidences separated
        combined_filepath = os.path.join(ns_dir, f"{ns}_shell_exports.sh")
        with open(combined_filepath, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Shell exports for namespace: {ns}\n")
            f.write(f"# Generated at: {timestamp}\n")
            f.write("# Usage: source this file or copy the variables you need\n\n")

            for conf_level in ["high", "medium", "low"]:
                items = confidence_groups[conf_level]
                if items:
                    f.write(f"\n# {'='*60}\n")
                    f.write(f"# {conf_level.upper()} CONFIDENCE ({len(items)} items)\n")
                    f.write(f"# {'='*60}\n\n")
                    f.write(format_shell_exports(items) + "\n")

        logger.info(f"Generated shell exports: {highlight_path(combined_filepath)}")
        files_created.append(combined_filepath)

        # 2. Generate separate files per confidence level
        for conf_level in ["high", "medium", "low"]:
            items = confidence_groups[conf_level]
            if items:
                conf_filepath = os.path.join(ns_dir, f"{ns}_{conf_level}_confidence.sh")
                with open(conf_filepath, 'w') as f:
                    f.write("#!/bin/bash\n")
                    f.write(f"# {conf_level.upper()} confidence exports for namespace: {ns}\n")
                    f.write(f"# Generated at: {timestamp}\n")
                    f.write(f"# Total items: {len(items)}\n\n")
                    f.write(format_shell_exports(items) + "\n")

                logger.debug(f"Generated {conf_level} confidence exports: {highlight_path(conf_filepath)}")
                files_created.append(conf_filepath)

    # 3. Generate a global summary file at the root
    global_filepath = os.path.join(output_dir, "ALL_SHELL_EXPORTS.sh")
    with open(global_filepath, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write(f"# All shell exports across all namespaces\n")
        f.write(f"# Generated at: {timestamp}\n")
        f.write("# Organized by: Namespace > Confidence Level\n\n")

        for ns in sorted(by_namespace.keys()):
            confidence_groups = by_namespace[ns]
            has_items = any(confidence_groups[c] for c in ["high", "medium", "low"])

            if has_items:
                f.write(f"\n# {'#'*70}\n")
                f.write(f"# NAMESPACE: {ns}\n")
                f.write(f"# {'#'*70}\n")

                for conf_level in ["high", "medium", "low"]:
                    items = confidence_groups[conf_level]
                    if items:
                        f.write(f"\n# --- {conf_level.upper()} CONFIDENCE ---\n")
                        f.write(format_shell_exports(items, include_comments=False) + "\n")

    logger.info(f"Generated global shell exports: {highlight_path(global_filepath)}")
    files_created.append(global_filepath)

    # Log summary
    total_high = sum(len(by_namespace[ns]["high"]) for ns in by_namespace)
    total_medium = sum(len(by_namespace[ns]["medium"]) for ns in by_namespace)
    total_low = sum(len(by_namespace[ns]["low"]) for ns in by_namespace)

    logger.info(f"Shell exports summary: {highlight_count(total_high)} high, {highlight_count(total_medium)} medium, {highlight_count(total_low)} low confidence")

    return {
        "namespaces": list(by_namespace.keys()),
        "counts": {
            "high": total_high,
            "medium": total_medium,
            "low": total_low
        },
        "files": files_created
    }


def process_docker_containers(args, output_dir):
    """Process Docker containers and extract environment variables."""
    # Test docker connectivity
    logger.info("Testing Docker connectivity...")
    test = run_docker(["info", "--format", "{{.ServerVersion}}"])
    if test is None:
        logger.error(f"Failed to connect to Docker. {highlight_error('Check that Docker is running.')}")
        return 1

    logger.info(highlight_success(f"Connected to Docker (version {test.strip()})."))

    # Get all containers
    logger.info("Fetching containers...")
    containers = get_docker_containers()

    if not containers:
        logger.warning("No containers found.")
        return 0

    # Display found containers
    container_display = ", ".join(highlight_container(c["name"]) for c in containers[:5])
    if len(containers) > 5:
        container_display += f", ... (+{len(containers) - 5} more)"
    logger.info(f"Found {highlight_count(len(containers))} containers: {container_display}")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    logger.debug(f"Output directory: {highlight_path(output_dir)}")

    # Track all classified results for summary
    all_classified = []
    use_consolidated = args.consolidated

    # Use "docker" as the namespace for consistency with the existing output format
    ns = "docker"
    ns_pods_data = []

    for container in containers:
        container_id = container["id"]
        container_name = container["name"]
        container_status = container["status"]

        # Only try to exec into running containers
        if not container_status.lower().startswith("up"):
            logger.warning(f"Skipping {highlight_container(container_name)} (status: {container_status})")
            continue

        logger.debug(f"Getting env vars from container: {highlight_container(container_name)}")
        env_vars = get_container_env_vars(container_id)

        if env_vars:
            if use_consolidated:
                # Just classify, don't write per-container files
                classified = classify_pod_env_vars(env_vars)
                ns_pods_data.append((container_name, classified))
            else:
                # Write per-container files (original behavior)
                classified = save_env_vars(output_dir, ns, container_name, env_vars)
            all_classified.append((ns, container_name, classified))
        else:
            logger.warning(f"Failed to get env vars from {highlight_container(container_name)}")

    # Save consolidated output if flag is set
    if use_consolidated and ns_pods_data:
        save_namespace_consolidated(output_dir, ns, ns_pods_data)

    # Generate summary report
    if all_classified:
        summary = generate_summary_report(output_dir, all_classified)

        # Generate JSON exports for vault API
        json_result = generate_vault_json(output_dir, all_classified, context="docker")

        # Generate shell exports if requested
        if args.shell_export:
            shell_result = generate_shell_exports(output_dir, all_classified)

        # Print quick stats
        total = sum(len(items) for items in summary.values())
        logger.info(f"Found {highlight_count(total)} vault candidates across {highlight_count(len(all_classified))} containers")
        logger.info(f"Deduplicated to {highlight_count(json_result['total_secrets'])} unique secrets (from {json_result['deduplicated_from']} occurrences)")
        for cls, items in summary.items():
            if items:
                logger.info(f"  - {highlight_classification(cls)}: {highlight_count(len(items))} items")

    logger.info(f"{highlight_success('Done!')} Environment variables saved to: {highlight_path(output_dir)}/")
    return 0


def main():
    args = get_args()

    # Set up logging based on verbosity flags
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
    setup_logging(log_level, no_color=args.no_color)

    output_dir = args.output

    # Handle test mode - auto-increment output directory
    if args.test:
        output_dir = get_next_test_output_dir(output_dir)
        logger.info(f"Test mode: using output directory {highlight_path(output_dir)}")

    # Docker mode
    if args.docker:
        return process_docker_containers(args, output_dir)

    # Kubernetes mode (original behavior)
    kubeconfig = args.kubeconfig
    context = args.context

    # Test kubectl connectivity
    logger.info("Testing kubectl connectivity...")
    test = run_kubectl(["cluster-info"], kubeconfig, context)
    if test is None:
        logger.error(f"Failed to connect to Kubernetes cluster. {highlight_error('Check your kubeconfig/context.')}")
        return 1
    logger.info(highlight_success("Connected to cluster successfully."))

    # Get namespaces
    if args.namespace:
        namespaces = args.namespace
        ns_display = ", ".join(highlight_namespace(ns) for ns in namespaces)
        logger.info(f"Using specified namespaces: {ns_display}")
    else:
        logger.info("Fetching all namespaces...")
        namespaces = get_namespaces(kubeconfig, context)
        ns_display = ", ".join(highlight_namespace(ns) for ns in namespaces)
        logger.info(f"Found {highlight_count(len(namespaces))} namespaces: {ns_display}")

    # Apply exclusions
    exclude_ns = args.exclude_namespace or []
    if exclude_ns:
        original_count = len(namespaces)
        namespaces = [ns for ns in namespaces if ns not in exclude_ns]
        excluded_count = original_count - len(namespaces)
        excluded_display = ", ".join(highlight_warning(ns) for ns in exclude_ns)
        logger.info(f"Excluded {highlight_count(excluded_count)} namespaces: {excluded_display}")
        ns_display = ", ".join(highlight_namespace(ns) for ns in namespaces)
        logger.info(f"Processing {highlight_count(len(namespaces))} namespaces: {ns_display}")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    logger.debug(f"Output directory: {highlight_path(output_dir)}")

    # Track all classified results for summary
    all_classified = []

    # Process each namespace
    use_consolidated = args.consolidated

    for ns in namespaces:
        logger.info(f"Processing namespace: {highlight_namespace(ns)}")
        pods = get_pods(ns, kubeconfig, context)

        if not pods:
            logger.warning(f"No pods found in namespace {highlight_namespace(ns)}")
            continue

        pods_display = ", ".join(highlight_pod(p) for p in pods[:5])
        if len(pods) > 5:
            pods_display += f", ... (+{len(pods) - 5} more)"
        logger.info(f"Found {highlight_count(len(pods))} pods in {highlight_namespace(ns)}: {pods_display}")

        # Collect pod data for this namespace (used for consolidated output)
        ns_pods_data = []

        for pod in pods:
            logger.debug(f"Getting env vars from pod: {highlight_pod(pod)}")
            env_vars = get_pod_env_vars(ns, pod, kubeconfig, context)

            if env_vars:
                if use_consolidated:
                    # Just classify, don't write per-pod files
                    classified = classify_pod_env_vars(env_vars)
                    ns_pods_data.append((pod, classified))
                else:
                    # Write per-pod files (original behavior)
                    classified = save_env_vars(output_dir, ns, pod, env_vars)
                all_classified.append((ns, pod, classified))
            else:
                logger.warning(f"Failed to get env vars from {highlight_pod(pod)} (pod may not be running)")

        # Save consolidated output for this namespace if flag is set
        if use_consolidated and ns_pods_data:
            save_namespace_consolidated(output_dir, ns, ns_pods_data)

    # Generate summary report
    if all_classified:
        summary = generate_summary_report(output_dir, all_classified)

        # Generate JSON exports for vault API
        json_result = generate_vault_json(output_dir, all_classified, context=context)

        # Generate shell exports if requested
        if args.shell_export:
            shell_result = generate_shell_exports(output_dir, all_classified)

        # Print quick stats
        total = sum(len(items) for items in summary.values())
        logger.info(f"Found {highlight_count(total)} vault candidates across {highlight_count(len(all_classified))} pods")
        logger.info(f"Deduplicated to {highlight_count(json_result['total_secrets'])} unique secrets (from {json_result['deduplicated_from']} occurrences)")
        for cls, items in summary.items():
            if items:
                logger.info(f"  - {highlight_classification(cls)}: {highlight_count(len(items))} items")

    logger.info(f"{highlight_success('Done!')} Environment variables saved to: {highlight_path(output_dir)}/")
    return 0


if __name__ == "__main__":
    exit(main())


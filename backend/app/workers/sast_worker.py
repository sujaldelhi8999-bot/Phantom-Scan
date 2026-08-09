"""
SAST Worker - Runs static analysis in sandbox using Semgrep and other tools.
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

import httpx


async def execute(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute SAST scan in sandbox."""
    scan_id = int(payload["scan_id"])
    source_config = payload.get("source_config", {})
    source_type = source_config.get("type", "local")
    target_path = source_config.get("path", "/app")
    languages = source_config.get("languages", [])
    frameworks = source_config.get("frameworks", [])
    exclude_patterns = source_config.get("exclude_patterns", [])
    include_patterns = source_config.get("include_patterns", [])

    findings = []
    artifacts = {}

    # Prepare working directory
    if source_type == "github":
        # Clone repository
        repo_url = source_config.get("repo_url")
        branch = source_config.get("branch", "main")
        work_dir = Path(tempfile.mkdtemp(prefix=f"sast-{scan_id}-"))
        await clone_repo(work_dir, repo_url, branch)
        target_path = str(work_dir)
    else:
        work_dir = Path(target_path)

    # Run Semgrep
    semgrep_findings = await run_semgrep(work_dir, languages, frameworks, exclude_patterns, include_patterns)
    findings.extend(semgrep_findings)
    artifacts["semgrep"] = {"findings": semgrep_findings, "count": len(semgrep_findings)}

    # Run truffleHog for secrets
    trufflehog_findings = await run_trufflehog(work_dir)
    findings.extend(trufflehog_findings)
    artifacts["trufflehog"] = {"findings": trufflehog_findings, "count": len(trufflehog_findings)}

    # Run gitleaks for secrets
    gitleaks_findings = await run_gitleaks(work_dir)
    findings.extend(gitleaks_findings)
    artifacts["gitleaks"] = {"findings": gitleaks_findings, "count": len(gitleaks_findings)}

    # Run dependency scanning (SCA)
    sca_findings = await run_sca_scan(work_dir)
    findings.extend(sca_findings)
    artifacts["sca"] = {"findings": sca_findings, "count": len(sca_findings)}

    # Run IaC scanning
    iac_findings = await run_iac_scan(work_dir)
    findings.extend(iac_findings)
    artifacts["iac"] = {"findings": iac_findings, "count": len(iac_findings)}

    # Save artifacts
    artifacts_path = work_dir / "sast_artifacts.json"
    artifacts_path.write_text(json.dumps(artifacts, indent=2))

    return {
        "status": "complete",
        "result": {
            "findings": findings,
            "artifacts": artifacts,
            "artifacts_path": str(artifacts_path),
            "source_type": source_type,
            "target_path": target_path,
            "total_findings": len(findings),
        },
    }


async def clone_repo(work_dir: Path, repo_url: str, branch: str) -> None:
    """Clone GitHub repository."""
    # Convert HTTPS URL to use token if available
    clone_url = repo_url
    if "github.com" in repo_url:
        token = os.getenv("GITHUB_TOKEN")
        if token:
            clone_url = repo_url.replace("https://github.com/", f"https://{token}@github.com/")

    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", "--branch", branch, clone_url, str(work_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to clone repo: {stderr.decode()}")


async def run_semgrep(
    work_dir: Path,
    languages: list[str],
    frameworks: list[str],
    exclude_patterns: list[str],
    include_patterns: list[str],
) -> list[dict[str, Any]]:
    """Run Semgrep static analysis."""
    # Build config
    config_args = ["--config=auto"]
    
    # Add language-specific configs
    if languages:
        for lang in languages:
            config_args.append(f"--config=p/{lang}")
    
    # Add framework configs
    if frameworks:
        for fw in frameworks:
            config_args.append(f"--config=p/{fw}")
    
    # Add exclude patterns
    for pattern in exclude_patterns:
        config_args.append(f"--exclude={pattern}")
    
    # Add include patterns
    for pattern in include_patterns:
        config_args.append(f"--include={pattern}")

    # Output as JSON
    config_args.extend(["--json", "--quiet"])

    cmd = ["semgrep", "scan"] + config_args + [str(work_dir)]
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(work_dir),
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode not in (0, 1):  # 0 = no findings, 1 = findings found
            return [{"error": f"Semgrep failed: {stderr.decode()}"}]
        
        if not stdout:
            return []
        
        result = json.loads(stdout.decode())
        findings = []
        
        for item in result.get("results", []):
            findings.append({
                "type": "sast",
                "tool": "semgrep",
                "rule_id": item.get("check_id"),
                "severity": map_semgrep_severity(item.get("extra", {}).get("severity", "WARNING")),
                "message": item.get("extra", {}).get("message", ""),
                "file_path": item.get("path"),
                "line_start": item.get("start", {}).get("line"),
                "line_end": item.get("end", {}).get("line"),
                "code_snippet": item.get("extra", {}).get("lines", ""),
                "rule_name": item.get("extra", {}).get("metadata", {}).get("name", ""),
                "references": item.get("extra", {}).get("metadata", {}).get("references", []),
                "cwe_ids": extract_cwe_ids(item.get("extra", {}).get("metadata", {})),
                "owasp_category": item.get("extra", {}).get("metadata", {}).get("owasp", ""),
            })
        
        return findings
    except Exception as e:
        return [{"error": f"Semgrep execution failed: {str(e)}"}]


def map_semgrep_severity(severity: str) -> str:
    """Map Semgrep severity to our severity levels."""
    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }
    return mapping.get(severity.upper(), "MEDIUM")


def extract_cwe_ids(metadata: dict[str, Any]) -> list[str]:
    """Extract CWE IDs from metadata."""
    cwes = []
    if "cwe" in metadata:
        cwe_val = metadata["cwe"]
        if isinstance(cwe_val, list):
            cwes.extend([str(c) for c in cwe_val])
        else:
            cwes.append(str(cwe_val))
    return cwes


async def run_trufflehog(work_dir: Path) -> list[dict[str, Any]]:
    """Run truffleHog for secrets detection."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "trufflehog", "filesystem", str(work_dir),
            "--json", "--no-update",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        
        findings = []
        for line in stdout.decode().strip().split("\n"):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                findings.append({
                    "type": "secret",
                    "tool": "trufflehog",
                    "detector_name": item.get("DetectorName", ""),
                    "secret_type": item.get("DetectorType", ""),
                    "file_path": item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                    "line_number": item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                    "matched_content": item.get("Raw", "")[:200],
                    "entropy": item.get("Entropy", 0),
                    "verified": item.get("Verified", False),
                })
            except json.JSONDecodeError:
                continue
        
        return findings
    except Exception as e:
        return [{"error": f"TruffleHog execution failed: {str(e)}"}]


async def run_gitleaks(work_dir: Path) -> list[dict[str, Any]]:
    """Run gitleaks for secrets detection."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect", "--source", str(work_dir),
            "--report-format", "json", "--verbose",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        
        findings = []
        if stdout:
            try:
                items = json.loads(stdout.decode())
                for item in items:
                    findings.append({
                        "type": "secret",
                        "tool": "gitleaks",
                        "detector_name": item.get("RuleID", ""),
                        "secret_type": item.get("Description", ""),
                        "file_path": item.get("File", ""),
                        "line_number": item.get("StartLine", 0),
                        "matched_content": item.get("Secret", "")[:200],
                        "entropy": item.get("Entropy", 0),
                        "verified": False,
                    })
            except json.JSONDecodeError:
                pass
        
        return findings
    except Exception as e:
        return [{"error": f"Gitleaks execution failed: {str(e)}"}]


async def run_sca_scan(work_dir: Path) -> list[dict[str, Any]]:
    """Run Software Composition Analysis (dependency scanning)."""
    findings = []
    
    # Python dependencies
    requirements_files = list(work_dir.rglob("requirements*.txt")) + list(work_dir.rglob("pyproject.toml")) + list(work_dir.rglob("setup.py"))
    for req_file in requirements_files:
        findings.extend(await scan_python_deps(req_file, work_dir))
    
    # Node.js dependencies
    package_files = list(work_dir.rglob("package.json"))
    for pkg_file in package_files:
        findings.extend(await scan_npm_deps(pkg_file, work_dir))
    
    return findings


async def scan_python_deps(req_file: Path, work_dir: Path) -> list[dict[str, Any]]:
    """Scan Python dependencies for vulnerabilities."""
    findings = []
    try:
        # Use pip-audit if available
        proc = await asyncio.create_subprocess_exec(
            "pip-audit", "-r", str(req_file), "--format", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(work_dir),
        )
        stdout, stderr = await proc.communicate()
        
        if stdout:
            items = json.loads(stdout.decode())
            for item in items:
                findings.append({
                    "type": "sca",
                    "tool": "pip-audit",
                    "package_name": item.get("name", ""),
                    "package_version": item.get("version", ""),
                    "ecosystem": "pypi",
                    "vulnerability_id": item.get("vulns", [{}])[0].get("id", ""),
                    "vulnerable_versions": item.get("vulns", [{}])[0].get("fix_versions", [""])[0] if item.get("vulns") else "",
                    "fixed_version": item.get("vulns", [{}])[0].get("fix_versions", [""])[0] if item.get("vulns") else "",
                    "cvss_score": None,
                    "advisory_url": item.get("vulns", [{}])[0].get("url", ""),
                })
    except Exception:
        pass
    return findings


async def scan_npm_deps(pkg_file: Path, work_dir: Path) -> list[dict[str, Any]]:
    """Scan npm dependencies for vulnerabilities."""
    findings = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "audit", "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(pkg_file.parent),
        )
        stdout, stderr = await proc.communicate()
        
        if stdout:
            items = json.loads(stdout.decode())
            for vuln_id, vuln in items.get("vulnerabilities", {}).items():
                findings.append({
                    "type": "sca",
                    "tool": "npm-audit",
                    "package_name": vuln.get("name", ""),
                    "package_version": vuln.get("version", ""),
                    "ecosystem": "npm",
                    "vulnerability_id": vuln_id,
                    "vulnerable_versions": vuln.get("range", ""),
                    "fixed_version": vuln.get("fixAvailable", {}).get("version", ""),
                    "cvss_score": None,
                    "advisory_url": f"https://github.com/advisories/{vuln_id}",
                })
    except Exception:
        pass
    return findings


async def run_iac_scan(work_dir: Path) -> list[dict[str, Any]]:
    """Run IaC scanning (Terraform, Kubernetes, Dockerfile)."""
    findings = []
    
    # Terraform
    tf_files = list(work_dir.rglob("*.tf")) + list(work_dir.rglob("*.tfvars"))
    if tf_files:
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "scan", "--config=p/terraform", "--json", "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(work_dir),
            )
            stdout, stderr = await proc.communicate()
            if stdout:
                items = json.loads(stdout.decode())
                for item in items.get("results", []):
                    findings.append({
                        "type": "iac",
                        "tool": "semgrep",
                        "resource_type": "terraform",
                        "file_path": item.get("path"),
                        "line_start": item.get("start", {}).get("line"),
                        "line_end": item.get("end", {}).get("line"),
                        "misconfiguration_type": item.get("extra", {}).get("metadata", {}).get("name", ""),
                        "platform": "terraform",
                    })
        except Exception:
            pass
    
    # Kubernetes
    k8s_files = list(work_dir.rglob("*.yaml")) + list(work_dir.rglob("*.yml"))
    k8s_files = [f for f in k8s_files if any(k in f.read_text(encoding="utf-8", errors="ignore")[:500] for k in ["apiVersion:", "kind:"])]
    if k8s_files:
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "scan", "--config=p/kubernetes", "--json", "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(work_dir),
            )
            stdout, stderr = await proc.communicate()
            if stdout:
                items = json.loads(stdout.decode())
                for item in items.get("results", []):
                    findings.append({
                        "type": "iac",
                        "tool": "semgrep",
                        "resource_type": "kubernetes",
                        "file_path": item.get("path"),
                        "line_start": item.get("start", {}).get("line"),
                        "line_end": item.get("end", {}).get("line"),
                        "misconfiguration_type": item.get("extra", {}).get("metadata", {}).get("name", ""),
                        "platform": "kubernetes",
                    })
        except Exception:
            pass
    
    return findings


def main() -> None:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        result = asyncio.run(execute(payload))
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
    except BaseException as exc:
        sys.stdout.write(json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":")))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
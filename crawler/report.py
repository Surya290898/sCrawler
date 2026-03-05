from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import pandas as pd

@dataclass
class PageFinding:
    url: str
    final_url: str
    status: int
    reason: str
    title: str
    content_type: str
    content_length: int
    scheme: str
    num_outlinks_internal: int
    num_outlinks_external: int
    forms_count: int
    has_password_form: bool
    password_form_over_http: bool
    hdr_csp: bool
    hdr_xfo: bool
    hdr_hsts: bool
    hdr_xcto: bool
    hdr_refpol: bool
    # NEW
    security_score: int

@dataclass
class Issue:
    url: str
    check_id: str
    title: str
    severity: str
    description: str
    recommendation: str

def to_dataframe(findings: List[PageFinding]) -> pd.DataFrame:
    return pd.DataFrame([asdict(f) for f in findings])

def to_csv(findings: List[PageFinding]) -> bytes:
    df = to_dataframe(findings)
    return df.to_csv(index=False).encode("utf-8")

def to_json(findings: List[PageFinding]) -> bytes:
    df = to_dataframe(findings)
    return df.to_json(orient="records", indent=2).encode("utf-8")

def issues_to_dataframe(issues: List[Issue]) -> pd.DataFrame:
    return pd.DataFrame([asdict(i) for i in issues])

def issues_to_csv(issues: List[Issue]) -> bytes:
    df = issues_to_dataframe(issues)
    return df.to_csv(index=False).encode("utf-8")

def issues_to_json(issues: List[Issue]) -> bytes:
    df = issues_to_dataframe(issues)
    return df.to_json(orient="records", indent=2).encode("utf-8")

def overall_site_score(findings: List[PageFinding]) -> int:
    """Weighted average leaning toward worst pages (square root dampening)."""
    if not findings:
        return 0
    scores = [max(0, min(100, f.security_score)) for f in findings]
    # Penalize low scores slightly more by using harmonic-like average
    denom = sum((101 - s) or 1 for s in scores)
    raw = 100 - (denom / len(scores))
    return int(max(0, min(100, raw)))

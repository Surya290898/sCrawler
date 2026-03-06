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

def to_dataframe(findings: List[PageFinding]) -> pd.DataFrame:
    return pd.DataFrame([asdict(f) for f in findings])

def to_csv(findings: List[PageFinding]) -> bytes:
    df = to_dataframe(findings)
    return df.to_csv(index=False).encode("utf-8")

def to_json(findings: List[PageFinding]) -> bytes:
    df = to_dataframe(findings)
    return df.to_json(orient="records", indent=2).encode("utf-8")

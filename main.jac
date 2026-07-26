"""GitHub repository security scanner backed by the trained CodeBERT model."""

import model_service;


obj ScanFinding {
    has title: str;
    has severity: str;
    has path: str;
    has line_start: int;
    has line_end: int;
    has confidence: float;
}


obj ScanResult {
    has repository: str;
    has device: str;
    has files_scanned: int;
    has windows_scanned: int;
    has elapsed_seconds: float;
    has findings: list[ScanFinding];
    has error_message: str = "";
}


def:pub scan_repository(repository: str) -> ScanResult {
    try {
        raw = model_service.scan_repository(repository);
    } except Exception as error {
        return ScanResult(
            repository=repository,
            device="",
            files_scanned=0,
            windows_scanned=0,
            elapsed_seconds=0.0,
            findings=[],
            error_message=str(error),
        );
    }
    raw_findings = raw["findings"] as list[dict[str, object]];
    findings: list[ScanFinding] = [];
    for item in raw_findings {
        findings.append(
            ScanFinding(
                title=item["title"] as str,
                severity=item["severity"] as str,
                path=item["path"] as str,
                line_start=item["line_start"] as int,
                line_end=item["line_end"] as int,
                confidence=item["confidence"] as float,
            )
        );
    }
    return ScanResult(
        repository=raw["repository"] as str,
        device=raw["device"] as str,
        files_scanned=raw["files_scanned"] as int,
        windows_scanned=raw["windows_scanned"] as int,
        elapsed_seconds=raw["elapsed_seconds"] as float,
        findings=findings,
    );
}

cl import "./styles.css";

cl def:pub app -> JsxElement {
    has repository: str = "";
    has analyzing: bool = False;
    has scan_result: ScanResult | None = None;
    has error_message: str = "";

    def update_repository(event: ChangeEvent) {
        repository = event.target.value;
        scan_result = None;
        error_message = "";
    }

    async def analyze_repository(event: FormEvent) {
        event.preventDefault();
        if analyzing {
            return;
        }
        requested_repository = repository;
        analyzing = True;
        scan_result = None;
        error_message = "";
        try {
            result = await scan_repository(requested_repository);
            if result.error_message {
                error_message = result.error_message;
            } else {
                scan_result = result;
            }
        } except Exception as error {
            error_message = f"Server request failed: {str(error)}";
        } finally {
            analyzing = False;
        }
    }

    return <main className="page">
        <section className="workspace">
            <form className="verify-form" onSubmit={analyze_repository}>
                <input
                    className="repo-input"
                    type="url"
                    value={repository}
                    onChange={update_repository}
                    placeholder="https://github.com/owner/repository"
                    aria-label="GitHub repository URL"
                    required
                />
                <button
                    className="verify-button"
                    type="submit"
                    disabled={analyzing}
                >
                    {"Analyzing" if analyzing else "Go"}
                </button>
            </form>

            <aside className="results" aria-live="polite">
                {if analyzing {
                    <div className="analyzing">
                        <span className="spinner" aria-hidden="true"></span>
                        <span>Cloning and scanning Jac files</span>
                    </div>
                } elif error_message {
                    <div className="error-state">
                        <strong>Scan could not run</strong>
                        <p>{error_message}</p>
                    </div>
                } elif scan_result is not None {
                    <div className="result-content">
                        <div className="result-heading">
                            <div>
                                <h1>
                                    {f"{len(scan_result.findings)} potential vulnerabilities"}
                                </h1>
                                <p className="scan-summary">
                                    {f"{scan_result.files_scanned} files · {scan_result.windows_scanned} windows · {scan_result.elapsed_seconds:.1f}s"}
                                </p>
                            </div>
                            <span className="scan-badge">
                                {f"CodeBERT · {scan_result.device}"}
                            </span>
                        </div>

                        {if len(scan_result.findings) == 0 {
                            <div className="clean-state">
                                No windows exceeded the configured threshold.
                            </div>
                        } else {
                            for (index, finding) in enumerate(scan_result.findings) {
                                <div className="finding" key={f"{finding.path}:{finding.line_start}:{index}"}>
                                    <span className={
                                        "severity severity-high"
                                        if finding.severity == "High"
                                        else "severity severity-medium"
                                    }>
                                        {finding.severity}
                                    </span>
                                    <div>
                                        <h2>{finding.title}</h2>
                                        <p>
                                            {f"{finding.path} · lines {finding.line_start}–{finding.line_end} · {finding.confidence * 100:.0f}%"}
                                        </p>
                                    </div>
                                </div>
                            }
                        }}
                    </div>
                } else {
                    <span className="empty-mark">—</span>
                }}
            </aside>
        </section>
    </main>;
}

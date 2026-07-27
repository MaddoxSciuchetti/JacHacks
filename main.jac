"""GitHub repository security scanner backed by the trained CodeBERT model."""

import model_service;


obj ScanFinding {
    has title: str;
    has severity: str;
    has path: str;
    has line_start: int;
    has line_end: int;
    has source_url: str;
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
                source_url=item["source_url"] as str,
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
cl import from "reagraph" { GraphCanvas }

cl def graph_file_paths(findings: list[ScanFinding]) -> list[str] {
    paths: list[str] = [];
    for finding in findings {
        if finding.path not in paths {
            paths.append(finding.path);
        }
    }
    return paths;
}

cl def reagraph_nodes(
    repository: str,
    findings: list[ScanFinding],
) -> list[dict[str, object]] {
    nodes: list[dict[str, object]] = [
        {
            "id": "repository",
            "label": "Repository",
            "subLabel": repository,
            "fill": "#2e2e2e",
            "size": 16,
        }
    ];
    file_paths = graph_file_paths(findings);
    for (file_index, file_path) in enumerate(file_paths) {
        nodes.append(
            {
                "id": f"file:{file_index}",
                "label": file_path.split("/")[-1],
                "subLabel": file_path,
                "fill": "#7a7a7a",
                "size": 12,
            }
        );
    }
    for (finding_index, finding) in enumerate(findings) {
        nodes.append(
            {
                "id": f"finding:{finding_index}",
                "label": finding.title,
                "subLabel": f"{finding.path} · {finding.confidence * 100:.0f}%",
                "fill": "#c94c4c" if finding.severity == "High" else "#d79b3b",
                "size": 10,
            }
        );
    }
    return nodes;
}

cl def reagraph_edges(
    findings: list[ScanFinding],
) -> list[dict[str, object]] {
    edges: list[dict[str, object]] = [];
    file_paths = graph_file_paths(findings);
    for (file_index, _file_path) in enumerate(file_paths) {
        edges.append(
            {
                "id": f"repository:file:{file_index}",
                "source": "repository",
                "target": f"file:{file_index}",
            }
        );
    }
    for (finding_index, finding) in enumerate(findings) {
        file_index = file_paths.index(finding.path);
        edges.append(
            {
                "id": f"file:{file_index}:finding:{finding_index}",
                "source": f"file:{file_index}",
                "target": f"finding:{finding_index}",
            }
        );
    }
    return edges;
}

cl def graph_finding_index(graph_node: dict[str, object]) -> int {
    node_id = graph_node["id"] as str;
    if node_id.startswith("finding:") {
        return int(node_id.split(":")[-1]);
    }
    return -1;
}

cl def:pub app -> JsxElement {
    has repository: str = "";
    has analyzing: bool = False;
    has scan_result: ScanResult | None = None;
    has error_message: str = "";
    has active_result_tab: str = "vulnerabilities";
    has selected_finding: int = -1;

    def update_repository(event: ChangeEvent) {
        repository = event.target.value;
        scan_result = None;
        error_message = "";
        active_result_tab = "vulnerabilities";
        selected_finding = -1;
    }

    def show_vulnerabilities(_event: MouseEvent) {
        active_result_tab = "vulnerabilities";
    }

    def show_graph(_event: MouseEvent) {
        active_result_tab = "graph";
    }

    def select_graph_node(graph_node: dict[str, object]) {
        selected_finding = graph_finding_index(graph_node);
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
        active_result_tab = "vulnerabilities";
        selected_finding = -1;
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
        <h1 className="app-title">Jac-Analyzer</h1>
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
                                <p className="scan-scope">
                                    Production Jac source only · docs, tests, examples, and fixtures excluded
                                </p>
                            </div>
                            <span className="scan-badge">
                                {f"CodeBERT · {scan_result.device}"}
                            </span>
                        </div>

                        <div className="result-tabs" role="tablist" aria-label="Scan result views">
                            <button
                                className={
                                    "result-tab result-tab-active"
                                    if active_result_tab == "vulnerabilities"
                                    else "result-tab"
                                }
                                type="button"
                                role="tab"
                                aria-selected={active_result_tab == "vulnerabilities"}
                                aria-controls="vulnerability-panel"
                                onClick={show_vulnerabilities}
                            >
                                {f"Security vulnerabilities ({len(scan_result.findings)})"}
                            </button>
                            <button
                                className={
                                    "result-tab result-tab-active"
                                    if active_result_tab == "graph"
                                    else "result-tab"
                                }
                                type="button"
                                role="tab"
                                aria-selected={active_result_tab == "graph"}
                                aria-controls="graph-panel"
                                onClick={show_graph}
                            >
                                Node graph
                            </button>
                        </div>

                        {if active_result_tab == "vulnerabilities" {
                            <div id="vulnerability-panel" role="tabpanel">
                                {if len(scan_result.findings) == 0 {
                                    <div className="clean-state">
                                        No windows exceeded the configured threshold.
                                    </div>
                                } else {
                                    for (index, finding) in enumerate(scan_result.findings) {
                                        <a
                                            className="finding"
                                            key={f"{finding.path}:{finding.line_start}:{index}"}
                                            href={finding.source_url}
                                            aria-label={f"Open {finding.title} in {finding.path} at lines {finding.line_start} through {finding.line_end}"}
                                        >
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
                                                <span className="finding-action">
                                                    Open vulnerable code
                                                </span>
                                            </div>
                                        </a>
                                    }
                                }}
                            </div>
                        } else {
                            graph_nodes = reagraph_nodes(
                                scan_result.repository,
                                scan_result.findings,
                            );
                            graph_edges = reagraph_edges(scan_result.findings);
                            graph_selections: list[str] = (
                                [f"finding:{selected_finding}"]
                                if selected_finding >= 0
                                else []
                            );
                            <div id="graph-panel" className="graph-panel" role="tabpanel">
                                {if len(scan_result.findings) == 0 {
                                    <div className="clean-state">
                                        The graph will appear when vulnerabilities are found.
                                    </div>
                                } else {
                                    <div className="graph-legend" aria-label="Graph legend">
                                        <span><span className="legend-dot legend-repository"></span>Repository</span>
                                        <span><span className="legend-dot legend-file"></span>File</span>
                                        <span><span className="legend-dot legend-high"></span>High</span>
                                        <span><span className="legend-dot legend-medium"></span>Medium</span>
                                    </div>
                                    <p className="graph-instructions">
                                        Drag the canvas to pan · scroll to zoom · drag nodes to rearrange · click a vulnerability for details
                                    </p>
                                    <div
                                        className="reagraph-canvas"
                                        aria-label="Interactive repository vulnerability graph"
                                    >
                                        <GraphCanvas
                                            nodes={graph_nodes}
                                            edges={graph_edges}
                                            selections={graph_selections}
                                            cameraMode="pan"
                                            layoutType="forceDirected2d"
                                            labelType="all"
                                            draggable={True}
                                            onNodeClick={select_graph_node}
                                        />
                                    </div>

                                    if selected_finding >= 0 {
                                        selected = scan_result.findings[selected_finding];
                                        <div className="graph-details" aria-live="polite">
                                            <div>
                                                <span className={
                                                    "severity severity-high"
                                                    if selected.severity == "High"
                                                    else "severity severity-medium"
                                                }>
                                                    {selected.severity}
                                                </span>
                                                <h2>{selected.title}</h2>
                                            </div>
                                            <p>{selected.path}</p>
                                            <dl>
                                                <div>
                                                    <dt>Lines</dt>
                                                    <dd>{f"{selected.line_start}–{selected.line_end}"}</dd>
                                                </div>
                                                <div>
                                                    <dt>Confidence</dt>
                                                    <dd>{f"{selected.confidence * 100:.0f}%"}</dd>
                                                </div>
                                            </dl>
                                            <a
                                                className="graph-details-link"
                                                href={selected.source_url}
                                            >
                                                Open vulnerable code
                                            </a>
                                        </div>
                                    } else {
                                        <p className="graph-hint">Select a vulnerability node to inspect it.</p>
                                    }
                                }}
                            </div>
                        }}
                    </div>
                } else {
                    <span className="empty-mark" key="empty-state">—</span>
                }}
            </aside>
        </section>
    </main>;
}

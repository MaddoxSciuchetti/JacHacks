# JacHacks

A Jac CodeBERT vulnerability classifier with a full-stack Jac interface for
scanning public GitHub repositories.

## Problem and use case

### The problem we observed

Jac lets a team express graph data, walkers, server endpoints, browser
components, and Python-library calls in the same language. That makes it fast
to build an AI or graph-backed application, but it also concentrates several
security boundaries in one `.jac` file:

- `walker:pub` and `def:pub` can expose operations without authentication;
- a walker can traverse and report sensitive graph nodes from `root`;
- client Jac can render browser content through JSX and raw HTML;
- server Jac can call Python modules such as `os`, `sqlite3`, `pickle`, and
  `urllib` directly; and
- code and values can move between client, server, and graph contexts.

Existing security scanners are usually optimized for established Python,
JavaScript, or Java patterns. A generic scanner may understand an individual
Python call but miss the Jac context around it—for example, that the call is
reachable through a public walker, that it reports data from a graph, or that
the same source file also contains a client-side sink. Manual review is also
difficult for teams adopting Jac because a small syntax choice can change a
trust boundary without producing a compiler error.

We therefore built Jac-Analyzer to answer a focused question before code is
merged or deployed:

> Does this production Jac source contain a known dangerous data flow or expose
> a sensitive graph or server operation across the wrong trust boundary?

### Concrete use case

Consider a team building a Jac application that stores integration credentials
as graph nodes. To support an administration screen, a developer adds a walker
that traverses from `root` and reports every credential. During a demo, the
walker is marked `walker:pub` so the screen works without a login. The
application compiles and the feature works, but an anonymous caller can now
invoke the walker and retrieve sensitive nodes from the shared guest graph.

In the same repository, another developer passes a URL from a public endpoint
to `urllib.request.urlopen`, while a client component sends a user-controlled
string to `unsafe_html`. These defects live in different execution contexts,
yet all appear as Jac source. Reviewing only the graph model, only the
generated Python, or only the browser bundle will not give the team a complete
view.

Before deployment, the team submits the public GitHub repository to
Jac-Analyzer. The scanner inspects production `.jac` files, identifies
candidate vulnerable regions, classifies their likely vulnerability type,
links each result to the relevant GitHub lines, and displays how findings
relate to files in a graph. This gives a maintainer a prioritized review queue;
it does not replace authentication tests, threat modeling, or a professional
security audit.

### Jac vulnerability classes exposed by this project

| Vulnerability | Jac pattern the scanner is trained to flag | What an attacker could gain |
| --- | --- | --- |
| Missing authentication | Sensitive `walker:pub` or `def:pub` operations, especially walkers that traverse and `report` graph nodes | Anonymous access to privileged behavior or graph data; possible cross-user data exposure through the shared guest root |
| Cross-site scripting | Untrusted values assembled into HTML and passed to client-side `unsafe_html(...)` in a JSX component | Script execution in another user's browser |
| Hardcoded secret | API keys, database passwords, signing material, or credentials stored directly in `.jac` source or a client-reachable value | Credentials recovered from source control, build artifacts, or a client bundle |
| OS command injection | Jac input interpolated into `os.system(...)` or a shell-enabled Python subprocess call | Arbitrary commands executed with the Jac server's privileges |
| SQL injection | User input formatted or concatenated into SQL passed through Python database libraries such as `sqlite3` | Unauthorized reading or modification of application data |
| Path traversal | User-controlled names joined to a base directory and opened without validating the resolved path | Reading or overwriting files outside the intended directory |
| Code injection | Untrusted strings passed to `exec(...)`, `eval(...)`, or an equivalent dynamic execution sink | Arbitrary code execution inside the server process |
| Unsafe deserialization | Attacker-controlled bytes loaded through Python `pickle` or a similarly executable deserializer | Arbitrary callable execution during object loading |
| Server-side request forgery | A caller-controlled URL fetched by server-side Jac through `urllib`, `requests`, or a similar Python client | Access to internal services, cloud metadata, or restricted network resources |
| Predictable security token | Tokens created with timestamps, weak random sources, or time-based UUIDs such as `uuid.uuid1()` | Guessing enrollment, reset, invitation, or session-like tokens |

These classes deliberately cover both Jac-specific trust-boundary mistakes
(`:pub`, graph traversal, `report`, client/server placement) and dangerous
Python capabilities that Jac can invoke directly. That combination is the
reason a Jac-aware classifier is useful instead of treating `.jac` as generic
text or scanning only generated output.

## Train on an H100 for up to one hour

Start from an H100 image that already has a CUDA-enabled PyTorch build. Clone
this repository, then run:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

mkdir -p artifacts
python -m zipfile -e \
  jac_codebert_pipeline_bundle.zip \
  artifacts
python -m pip install -r \
  artifacts/jac_codebert_pipeline_bundle/requirements-jac-codebert.txt

./scripts/train_h100.sh
```

The script:

1. verifies that PyTorch can see CUDA and prints the GPU name;
2. extracts and validates the pipeline and dataset locations;
3. downloads and caches `microsoft/codebert-base`;
4. runs a one-epoch frozen-encoder smoke test;
5. fine-tunes the binary and vulnerability-type stages with a combined
   optimizer-time cap of 3,600 seconds;
6. stops earlier if validation macro F1 stops improving;
7. writes metrics, predictions, confusion matrices, models, and a portable
   archive.

The one-hour cap is divided equally between the two classifier stages. Model
download, preprocessing, evaluation, and result packaging are outside that
timer. Override it with `TRAIN_SECONDS`, for example:

```sh
TRAIN_SECONDS=1800 ./scripts/train_h100.sh
```

## Read and download the results

The important outputs are:

```text
runs/jac-codebert/summary.json
runs/jac-codebert/prepared_split_audit.json
runs/jac-codebert/binary/classification_report.json
runs/jac-codebert/binary/confusion_matrix.json
runs/jac-codebert/binary/validation_predictions.csv
runs/jac-codebert/type/classification_report.json
runs/jac-codebert/type/confusion_matrix.json
runs/jac-codebert/type/validation_predictions.csv
runs/jac-codebert/binary/model/
runs/jac-codebert/type/model/
runs/jac-codebert.results.tar.gz
```

Download `runs/jac-codebert.results.tar.gz` from the GPU host. Check
`summary.json` for binary and type macro F1, then inspect the per-class reports
and false positives before treating the model as usable.

## Run the trained model in the front end

If training and serving happen on the same machine:

```sh
source .venv/bin/activate
export JAC_MODEL_DIR="$PWD/runs/jac-codebert"
export JAC_PIPELINE_FILE="$PWD/artifacts/jac_codebert_pipeline_bundle/jac_codebert_pipeline.py"

jac install
jac start main.jac --profile prod --port 8003
```

If the results were trained elsewhere:

```sh
mkdir -p runs/jac-codebert artifacts
tar -xzf jac-codebert.results.tar.gz -C runs/jac-codebert
python -m zipfile -e \
  jac_codebert_pipeline_bundle.zip \
  artifacts

export JAC_MODEL_DIR="$PWD/runs/jac-codebert"
export JAC_PIPELINE_FILE="$PWD/artifacts/jac_codebert_pipeline_bundle/jac_codebert_pipeline.py"

jac install
jac start main.jac --profile prod --port 8003
```

Open the printed local URL and enter a public
`https://github.com/owner/repository` URL. The server clones only that public
GitHub repository, scans its production `.jac` files, and returns model
findings to both a vulnerability list and a node graph in the Jac UI.
Documentation, tests, examples, fixtures, benchmarks, generated code, and
vendored directories are excluded before files are sent to the model.
Each successful scan also receives a security score from 0 to 100. The score
uses the strongest confidence for each distinct file and vulnerability
category, weights high-severity evidence more heavily, and discounts additional
signals so overlapping model windows are not treated as independent
vulnerabilities. A higher score means the model found less evidence of
vulnerabilities; it is not a security certification.

Use `jac dev main.jac --port 8003` only while changing the interface. Hot
reload intentionally replaces client state and can force a full refresh when
the number of `has` state fields changes or an intermediate edit does not
compile. Restart with the stable command above after development changes.

Optional inference controls:

```sh
export JAC_SCAN_THRESHOLD=0.60
export JAC_SCAN_MAX_FILES=200
export JAC_SCAN_MAX_FILE_BYTES=262144
export JAC_SCAN_MIN_FREE_BYTES=268435456
export JAC_SCAN_MAX_WINDOWS=1000
export JAC_SCAN_BATCH_SIZE=64
export JAC_SCAN_MAX_FINDINGS=50
export JAC_INFERENCE_REQUIRE_CUDA=1
```

The model is trained on a small synthetic corpus. Its output is a candidate
security signal, not proof that a repository is safe or vulnerable.

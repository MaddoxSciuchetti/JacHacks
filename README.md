# JacHacks

A Jac CodeBERT vulnerability classifier with a full-stack Jac interface for
scanning public GitHub repositories.

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

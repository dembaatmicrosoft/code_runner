import azure.functions as func
import logging
import tempfile
import uuid
import os
import json
import subprocess
import sys

# Constants
MAX_SCRIPT_BYTES = 256 * 1024   # 256 KiB
MAX_TIMEOUT_S = 300              # 5 minutes

app = func.FunctionApp()  # V2 programming model


@app.function_name(name="RunPythonScript")
@app.route(
    route="run",
    methods=["POST"],
    auth_level=func.AuthLevel.ANONYMOUS
)
def run_script(req: func.HttpRequest) -> func.HttpResponse:
    """Runs user-supplied Python code in a subprocess, returns exit_code/stdout/stderr."""

    logging.info("Received request to run python script.")

    # Determine mode: JSON vs. raw-text
    content_type = req.headers.get("content-type", "")
    if content_type.startswith("text/plain"):
        # Raw mode: code = body, timeout in query
        try:
            script = req.get_body().decode("utf-8")
        except Exception:
            return func.HttpResponse(
                json.dumps({"error": "Unable to read request body as UTF-8 text."}),
                status_code=400,
                mimetype="application/json"
            )
        # parse timeout_s from query
        timeout_s = req.params.get("timeout_s", None)
        if timeout_s is None:
            timeout_s = 60
        else:
            try:
                timeout_s = int(timeout_s)
            except ValueError:
                return func.HttpResponse(
                    json.dumps({"error": "`timeout_s` query parameter must be integer."}),
                    status_code=400,
                    mimetype="application/json"
                )
    else:
        # JSON mode
        try:
            body = req.get_json()
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "Request body must be valid JSON."}),
                status_code=400,
                mimetype="application/json"
            )

        script = body.get("script")
        if not isinstance(script, str):
            return func.HttpResponse(
                json.dumps({"error": "`script` field is required and must be a string."}),
                status_code=400,
                mimetype="application/json"
            )

        # Timeout parsing
        timeout_s = body.get("timeout_s", 60)
        try:
            timeout_s = int(timeout_s)
        except (ValueError, TypeError):
            return func.HttpResponse(
                json.dumps({"error": "`timeout_s` must be an integer."}),
                status_code=400,
                mimetype="application/json"
            )

    # Validate timeout
    if timeout_s <= 0:
        return func.HttpResponse(
            json.dumps({"error": "`timeout_s` must be > 0."}),
            status_code=400,
            mimetype="application/json"
        )
    if timeout_s > MAX_TIMEOUT_S:
        logging.warning(f"Clamping timeout {timeout_s}s → {MAX_TIMEOUT_S}s.")
        timeout_s = MAX_TIMEOUT_S

    # Validate script size
    script_bytes = script.encode("utf-8")
    if len(script_bytes) > MAX_SCRIPT_BYTES:
        return func.HttpResponse(
            json.dumps({
                "error": f"Script too large: {len(script_bytes)} bytes > {MAX_SCRIPT_BYTES} bytes."
            }),
            status_code=413,
            mimetype="application/json"
        )

    # Write script to a uniquely named temp file
    unique_id = str(uuid.uuid4())
    tmp_dir = tempfile.gettempdir()
    script_path = os.path.join(tmp_dir, f"user_script_{unique_id}.py")
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
    except Exception as e:
        logging.error(f"Failed to write script to disk: {e}")
        return func.HttpResponse(
            json.dumps({"error": "Internal error writing script to disk."}),
            status_code=500,
            mimetype="application/json"
        )

    # Prepare subprocess command (use same interpreter)
    python_exe = sys.executable or "python3"
    cmd = [python_exe, "-X", "utf8", script_path]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    # Execute script with timeout
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=tmp_dir,
            timeout=timeout_s,
            check=False,
            env=env,              # <— only needed for Option A if you skip -X utf8
        )
        exit_code = completed.returncode
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")

    except subprocess.TimeoutExpired as te:
        exit_code = 124
        stdout = te.stdout.decode("utf-8", errors="replace") if te.stdout else ""
        stderr = (te.stderr.decode("utf-8", errors="replace") if te.stderr else "") + "\n[Error: Script timed out]"

    except Exception as e:
        logging.exception("Unexpected error running user script.")
        exit_code = -1
        stdout = ""
        stderr = f"[Internal execution error] {str(e)}"

    finally:
        # Cleanup
        try:
            os.remove(script_path)
        except Exception:
            pass

    # Build response
    result = {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr
    }
    return func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json"
    )


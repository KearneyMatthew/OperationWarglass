# app.py
import os
import time
import uuid
import threading
import queue
import subprocess
import json
from flask import Flask, request, jsonify, Response, send_from_directory, abort

# Configuration
RUNS_DIR = "runs"
ORCHESTRATOR = "orchestrator_stub.py"
HOST = "0.0.0.0"
PORT = 8000

# Create Flask app
app = Flask(__name__)
os.makedirs(RUNS_DIR, exist_ok=True)

runs = {}
runs_lock = threading.Lock()

print("Flask root path:", app.root_path)
print("Current working dir:", os.getcwd())
print("Index exists:", os.path.exists('index.html'))

@app.route("/")
def index():
    return send_from_directory('.', 'index.html')

def reader_thread(proc, q, logfile_path, run_id):
    """
    Read subprocess stdout/stderr, push structured JSON to queue, and write log file.
    Handles both JSON output and plain text fallback.
    """
    try:
        with open(logfile_path, "a", encoding="utf-8") as f:
            for raw_line in iter(proc.stdout.readline, ''):
                if not raw_line:
                    break
                text = raw_line.rstrip() if isinstance(raw_line, str) else raw_line.decode(errors="replace").rstrip()
                f.write(text + "\n")
                f.flush()
                try:
                    obj = json.loads(text)
                    try:
                        q.put(obj, block=False)
                    except queue.Full:
                        app.logger.warning("Queue full for %s — dropping event", run_id)
                except json.JSONDecodeError:
                    try:
                        q.put({"type": "log", "message": text}, block=False)
                    except queue.Full:
                        app.logger.warning("Queue full for %s — dropping log line", run_id)
    except Exception as e:
        app.logger.exception("Reader thread exception for %s", run_id)
        # try to notify via the queue; if queue is invalid/full, replace it
        try:
            q.put({"type": "error", "message": f"Reader error: {e}"}, block=False)
        except Exception:
            with runs_lock:
                meta = runs.get(run_id)
                if meta is not None:
                    new_q = queue.Queue(maxsize=5000)
                    meta["queue"] = new_q
                    q = new_q
            try:
                q.put({"type": "error", "message": f"Reader error (replaced queue): {e}"}, block=False)
            except Exception:
                app.logger.exception("Failed to put error into replacement queue for %s", run_id)

    proc.wait()
    q.put({"type": "complete", "message": "Run finished"})

    with runs_lock:
        meta = runs.get(run_id)
        if meta is not None:
            meta["finished"] = True


@app.route("/simulate", methods=["POST"])
def simulate():
    """
    Start a single orchestrator run with readable run ID.
    Rejects if another run is active.
    """
    data = request.get_json(force=True)
    attack = data.get("attack")
    purpose = data.get("purpose")
    defense = data.get("defense")

    if not all([attack, purpose, defense]):
        return jsonify({"error": "attack, purpose, and defense are required"}), 400

    with runs_lock:
        for rid, meta in runs.items():
            if meta.get("proc") and meta["proc"].poll() is None:
                return jsonify({
                    "error": "Another run is already in progress",
                    "active_run_id": rid
                }), 409

    def short_token(s, limit=16):
        t = str(s).strip().lower().replace(" ", "_")
        t = "".join(ch for ch in t if (ch.isalnum() or ch in "_-"))
        return t[:limit]

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    run_id = f"{timestamp}_{short_token(attack,12)}-{short_token(purpose,20)}-{short_token(defense,12)}-{uuid.uuid4().hex[:6]}"
    logfile = os.path.join(RUNS_DIR, f"run-{run_id}.log")

    cmd = [
        "python3", ORCHESTRATOR,
        "--attack", attack,
        "--purpose", purpose,
        "--defense", defense,
        "--run-id", run_id
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True
        )
    except Exception as e:
        return jsonify({"error": f"Failed to start orchestrator: {e}"}), 500

    q = queue.Queue(maxsize=5000)  # bounded for stability
    with runs_lock:
        runs[run_id] = {"queue": q, "proc": proc, "logfile": logfile}

    t = threading.Thread(target=reader_thread, args=(proc, q, logfile, run_id), daemon=True)
    t.start()

    return jsonify({
        "run_id": run_id,
        "logfile": logfile,
        "attack": attack,
        "purpose": purpose,
        "defense": defense,
        "start_time": timestamp
    })

@app.route("/stream/<run_id>")
def stream(run_id):
    with runs_lock:
        meta = runs.get(run_id)
    if not meta:
        return abort(404, description="Run ID not found")

    # Minimal subscriber guard to prevent duplicate streams for same run
    with runs_lock:
        subs = meta.get("subscribers", 0)
        if subs >= 1:
            # reject additional subscribers to avoid duplicate outputs
            return abort(409, description="Another stream subscriber is already connected for this run")
        meta["subscribers"] = subs + 1

    q = meta["queue"]

    def event_stream():
        try:
            yield "data: " + json.dumps({"type": "info", "message": "stream-open"}) + "\n\n"
            while True:
                try:
                    obj = q.get(timeout=0.5)
                except queue.Empty:
                    # Re-fetch meta under the lock in case it was removed/updated concurrently
                    with runs_lock:
                        current_meta = runs.get(run_id)
                    # If the run was removed, exit cleanly
                    if current_meta is None:
                        break

                    proc = current_meta.get("proc")
                    finished = current_meta.get("finished", False)

                    # If the process has exited and queue is empty, break
                    if (proc is not None and proc.poll() is not None) and q.empty():
                        break

                    # Send keepalive and continue waiting
                    yield ": keepalive\n\n"
                    continue

                # At this point we have an obj from the queue; send it
                try:
                    yield f"data: {json.dumps(obj)}\n\n"
                except (GeneratorExit, BrokenPipeError, ConnectionResetError):
                    break

                # Only end the stream when the orchestrator signals the run is finished
                if isinstance(obj, dict):
                    # run-complete signal is "finished" in orchestrator_stub.py
                    if obj.get("type") == "finished":
                        break
                    # backwards-compat: if some orchestrator uses complete as final marker,
                    # detect an explicit run-level message (optional)
                    if obj.get("type") == "complete" and obj.get("message", "").lower().startswith("run finished"):
                        break

        finally:
            # decrement subscribers and cleanup run
            with runs_lock:
                meta = runs.get(run_id)
                if meta:
                    meta["subscribers"] = max(0, meta.get("subscribers", 1) - 1)
                runs.pop(run_id, None)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/logs", methods=["GET"])
def list_logs():
    files = [{"name": fn, "mtime": os.path.getmtime(os.path.join(RUNS_DIR, fn))}
             for fn in os.listdir(RUNS_DIR) if os.path.isfile(os.path.join(RUNS_DIR, fn))]
    files.sort(key=lambda x: x["mtime"], reverse=True)
    return jsonify(files)

@app.route("/log")
def get_log():
    filename = request.args.get("file")
    if not filename:
        return abort(400, description="file parameter is required")
    path = os.path.join(RUNS_DIR, filename)
    if not os.path.exists(path) or not os.path.isfile(path):
        return abort(404, description="file not found")
    return send_from_directory(RUNS_DIR, filename, mimetype="text/plain")

if __name__ == "__main__":
    from pyngrok import ngrok
    import atexit

    PORT = 8000
    HOST = "0.0.0.0"

    # Start ngrok tunnel
    public_url = ngrok.connect(PORT)
    print(f" * ngrok tunnel running: {public_url}")

    # Ensure ngrok stops when app exits
    atexit.register(lambda: ngrok.disconnect(public_url))
    atexit.register(lambda: ngrok.kill())

    # Start Flask app
    app.run(host=HOST, port=PORT, threaded=True)



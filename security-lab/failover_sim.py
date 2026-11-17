"""LOCAL SIMULATION, not production availability."""

import json
import queue
import random
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from statistics import mean

from flask import Flask, jsonify
from werkzeug.serving import WSGIRequestHandler, make_server

SIMULATION_LABEL = "LOCAL SIMULATION, not production availability."
LAB_DIR = Path(__file__).resolve().parent
RESULTS_FILE = LAB_DIR / "failover_results.json"
PRIMARY_ID = "primary"
SECONDARY_ID = "secondary"
PRIMARY_PORT = 5101
SECONDARY_PORT = 5102
POLL_INTERVAL_SECONDS = 0.2
REQUEST_TIMEOUT_SECONDS = 0.15
FAILURE_THRESHOLD = 3
TRIAL_COUNT = 20
MIN_STOP_DELAY_SECONDS = 0.25
MAX_STOP_DELAY_SECONDS = 0.75


class QuietRequestHandler(WSGIRequestHandler):
    def log(self, log_type, message, *args):
        pass


def _create_health_app(service_id):
    app = Flask(f"failover_{service_id}")

    @app.get("/health")
    def health():
        return jsonify({"id": service_id, "status": 200}), 200

    return app


def _start_server(port, service_id):
    server = make_server(
        "127.0.0.1",
        port,
        _create_health_app(service_id),
        threaded=True,
        request_handler=QuietRequestHandler,
    )
    server_thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        name=f"{service_id}-server",
        daemon=True,
    )
    server_thread.start()
    return server, server_thread


def _stop_server(server, server_thread):
    server.shutdown()
    server.server_close()
    server_thread.join(timeout=2)


def _is_healthy(url, expected_id):
    try:
        with urllib.request.urlopen(
            url, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            if response.status != 200:
                return False
            payload = json.loads(response.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ):
        return False

    return (
        isinstance(payload, dict)
        and payload.get("id") == expected_id
        and payload.get("status") == 200
    )


def _client_loop(stop_event, primary_ready, result_queue):
    primary_url = f"http://127.0.0.1:{PRIMARY_PORT}/health"
    secondary_url = f"http://127.0.0.1:{SECONDARY_PORT}/health"
    target_url = primary_url
    target_id = PRIMARY_ID
    consecutive_failures = 0

    while not stop_event.is_set():
        request_started = time.perf_counter()
        if _is_healthy(target_url, target_id):
            if target_id == PRIMARY_ID:
                consecutive_failures = 0
                primary_ready.set()
            else:
                result_queue.put(time.perf_counter())
                return
        elif target_id == PRIMARY_ID:
            consecutive_failures += 1
            if consecutive_failures >= FAILURE_THRESHOLD:
                target_url = secondary_url
                target_id = SECONDARY_ID

        elapsed = time.perf_counter() - request_started
        stop_event.wait(max(0.0, POLL_INTERVAL_SECONDS - elapsed))


def _run_trial():
    primary_server, primary_thread = _start_server(
        PRIMARY_PORT, PRIMARY_ID
    )
    client_stop = threading.Event()
    primary_ready = threading.Event()
    result_queue = queue.Queue()

    def client_worker():
        try:
            _client_loop(client_stop, primary_ready, result_queue)
        except Exception as error:
            result_queue.put(error)

    client_thread = threading.Thread(
        target=client_worker,
        name="failover-client",
        daemon=True,
    )
    primary_stopped = False
    client_thread.start()

    try:
        if not primary_ready.wait(timeout=3):
            raise RuntimeError("Primary health endpoint did not become ready.")

        time.sleep(random.uniform(
            MIN_STOP_DELAY_SECONDS, MAX_STOP_DELAY_SECONDS
        ))
        failure_started = time.perf_counter()
        _stop_server(primary_server, primary_thread)
        primary_stopped = True

        result = result_queue.get(timeout=5)
        if isinstance(result, Exception):
            raise result
        return result - failure_started
    finally:
        client_stop.set()
        if not primary_stopped:
            _stop_server(primary_server, primary_thread)
        client_thread.join(timeout=2)


def run_simulation():
    secondary_server, secondary_thread = _start_server(
        SECONDARY_PORT, SECONDARY_ID
    )
    failover_times = []
    try:
        for _ in range(TRIAL_COUNT):
            failover_times.append(_run_trial())
    finally:
        _stop_server(secondary_server, secondary_thread)

    summary = {
        "label": SIMULATION_LABEL,
        "trials": TRIAL_COUNT,
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "consecutive_failures_before_switch": FAILURE_THRESHOLD,
        "failover_time_seconds": {
            "min": min(failover_times),
            "mean": mean(failover_times),
            "max": max(failover_times),
        },
        "trial_times_seconds": failover_times,
    }
    RESULTS_FILE.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def main():
    print(SIMULATION_LABEL)
    summary = run_simulation()
    times = summary["failover_time_seconds"]
    print(f"Trials: {summary['trials']}")
    print(
        "Failover time (seconds): "
        f"min={times['min']:.3f}, "
        f"mean={times['mean']:.3f}, "
        f"max={times['max']:.3f}"
    )
    print(f"Results saved to {RESULTS_FILE}")


if __name__ == "__main__":
    main()

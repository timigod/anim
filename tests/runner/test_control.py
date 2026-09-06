from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

import pytest

import ebm_audit.adapters.invocation as invocation
from ebm_audit.adapters import WorkerCommand, WorkerInvoker
from ebm_audit.errors import ExitCode
from ebm_audit.runner import (
    ExecutionCancelled,
    ExecutionControl,
    ExecutionPhase,
    ExecutionProgress,
    MemoryAdmissionError,
)


@pytest.mark.parametrize(
    ("budget", "reservation"),
    [(None, 1), (1, None), (True, 1), (1, False), (0, 1), (-1, 1), (1.5, 1)],
)
def test_invalid_memory_admission_is_safe(budget, reservation):
    with pytest.raises(MemoryAdmissionError) as caught:
        ExecutionControl(memory_budget_bytes=budget, per_worker_memory_bytes=reservation)
    assert caught.value.exit_code is ExitCode.INVALID_INPUT_OR_SPECIFICATION
    assert caught.value.invocation_observation is None


def test_memory_admission_never_raises_planned_ceiling():
    assert ExecutionControl().effective_parallel_workers(3) == 3
    assert ExecutionControl(
        memory_budget_bytes=1000, per_worker_memory_bytes=1
    ).effective_parallel_workers(3) == 3


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_signal_cancels_cooperatively_and_restores_handler(signum):
    control = ExecutionControl()
    previous = signal.getsignal(signum)
    with control.signal_handlers():
        os.kill(os.getpid(), signum)
        os.kill(os.getpid(), signum)
        assert control.cancellation_requested
        with pytest.raises(ExecutionCancelled):
            control.raise_if_cancelled()
    assert signal.getsignal(signum) == previous


def test_signal_context_restores_handlers_on_exception():
    previous = [signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)]
    with pytest.raises(ValueError), ExecutionControl().signal_handlers():
        raise ValueError("synthetic failure")
    assert [signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)] == previous
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lambda: ExecutionControl().signal_handlers().__enter__())
        with pytest.raises(RuntimeError, match="main thread"):
            future.result()


def test_progress_is_safe_and_observer_failure_does_not_replace_outcome():
    progress = ExecutionProgress(ExecutionPhase.RUNNING, 3, 2, 1, 2)
    assert json.loads(json.dumps(asdict(progress))) == {
        "phase": "RUNNING",
        "planned_candidates": 3,
        "submitted_candidates": 2,
        "persisted_candidates": 1,
        "effective_parallel_workers": 2,
    }

    def broken(_event):
        raise ValueError("sensitive-untrusted-callback-text")

    control = ExecutionControl(progress_callback=broken)
    control._emit(progress)
    assert control.progress_callback_failures == 1
    assert not control.cancellation_requested
    assert "sensitive" not in repr(control)


def test_precancelled_invocation_does_not_start_a_process(monkeypatch):
    control = ExecutionControl()
    control.request_cancel()

    def forbidden(*_args, **_kwargs):
        pytest.fail("Cancellation must prevent worker launch.")

    monkeypatch.setattr(invocation.subprocess, "Popen", forbidden)
    invoker = WorkerInvoker(
        WorkerCommand.from_tokens((sys.executable, "-c", "pass")), execution_control=control
    )
    with pytest.raises(ExecutionCancelled) as caught:
        invoker.invoke(command="describe", payload_schema_version=None, payload={})
    assert caught.value.code == "EXECUTION.CANCELLED"
    assert caught.value.invocation_observation is None
    assert caught.value.__context__ is None


def _read_linux_proc_file(directory_fd, name):
    with os.fdopen(os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory_fd), "rb") as stream:
        return stream.read()


def _linux_process_exited(directory_fd):
    try:
        stat = _read_linux_proc_file(directory_fd, "stat")
    except (FileNotFoundError, ProcessLookupError):
        return True
    # comm is parenthesized and may itself contain spaces or parentheses.
    return stat.rsplit(b")", 1)[1].split()[0] in {b"Z", b"X"}


@pytest.mark.skipif(os.name != "posix", reason="POSIX worker process groups required")
@pytest.mark.parametrize(
    "without_pidfd_open",
    [False, True] if sys.platform == "linux" else [False],
    ids=lambda missing: "without-pidfd-open" if missing else "default",
)
def test_cancellation_kills_and_reaps_worker_ignoring_sigterm(
    tmp_path, monkeypatch, without_pidfd_open
):
    if sys.platform == "linux" and not Path("/usr/bin/bwrap").is_file():
        pytest.skip("Linux worker execution requires bubblewrap containment.")
    if without_pidfd_open:
        monkeypatch.delattr(os, "pidfd_open", raising=False)
        assert not hasattr(os, "pidfd_open")
    worker_file = tmp_path / "slow_worker.py"
    worker_file.write_text(
        "import os, signal, sys, time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        # Bubblewrap preserves the host /proc mount in the containment plan.
        # /proc/self therefore identifies this worker to the observing parent,
        # while os.getpid() alone would identify it only inside the PID namespace.
        "pid = os.readlink('/proc/self') if sys.platform == 'linux' else str(os.getpid())\n"
        "Path('.cancel-test-ready.tmp').write_text(pid)\n"
        "Path('.cancel-test-ready.tmp').replace('.cancel-test-ready')\n"
        "while True: time.sleep(0.05)\n"
    )
    real_popen = subprocess.Popen
    started = threading.Event()
    processes = []
    ready_paths = []

    def capture(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        processes.append(process)
        ready_paths.append(Path(kwargs["cwd"]) / ".cancel-test-ready")
        started.set()
        return process

    monkeypatch.setattr(invocation.subprocess, "Popen", capture)
    control = ExecutionControl()
    invoker = WorkerInvoker(
        WorkerCommand.from_tokens((sys.executable, str(worker_file))),
        timeout_seconds=60,
        execution_control=control,
    )
    worker_pidfd = None
    worker_proc_fd = None
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            invoker.invoke,
            command="describe",
            payload_schema_version=None,
            payload={"expected_identity": None},
        )
        try:
            assert started.wait(5)
            deadline = time.monotonic() + 5
            while not ready_paths[0].exists() and time.monotonic() < deadline:
                if future.done():
                    future.result()
                time.sleep(0.01)
            assert ready_paths[0].exists()
            worker_pid = int(ready_paths[0].read_text())
            worker_exit = None
            if sys.platform == "linux":
                # Track the actual worker, not the Bubblewrap supervisor's
                # return code or process group (the worker has a new session).
                proc = Path("/proc") / str(worker_pid)
                # Pin this process's procfs directory: a reused PID cannot make
                # later reads observe a different process. This also works on
                # Python builds without the optional os.pidfd_open wrapper.
                worker_proc_fd = os.open(proc, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                assert os.fsencode(worker_file) in _read_linux_proc_file(
                    worker_proc_fd, "cmdline"
                ).split(b"\0")
                status = _read_linux_proc_file(worker_proc_fd, "status").decode().splitlines()
                ignored = next(line.split()[1] for line in status if line.startswith("SigIgn:"))
                assert int(ignored, 16) & (1 << (signal.SIGTERM - 1))
                assert worker_pid != processes[0].pid
                assert not _linux_process_exited(worker_proc_fd)
                if hasattr(os, "pidfd_open"):
                    worker_pidfd = os.pidfd_open(worker_pid)
                    worker_exit = select.poll()
                    worker_exit.register(worker_pidfd, select.POLLIN)
                    assert not worker_exit.poll(0)
            else:
                assert worker_pid == processes[0].pid
            cancellation_time = time.monotonic()
            control.request_cancel()
            with pytest.raises(ExecutionCancelled) as caught:
                future.result(timeout=4)
            assert time.monotonic() - cancellation_time < 4
            assert caught.value.exit_code is ExitCode.PARTIAL
            assert caught.value.invocation_observation is None
            assert caught.value.__context__ is None
            if worker_exit is not None:
                events = worker_exit.poll(1000)
                assert len(events) == 1 and events[0][0] == worker_pidfd
                assert events[0][1] & select.POLLIN
            if worker_proc_fd is not None:
                deadline = time.monotonic() + 1
                while not _linux_process_exited(worker_proc_fd) and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert _linux_process_exited(worker_proc_fd)
                assert processes[0].returncode in {-signal.SIGTERM, -signal.SIGKILL}
            else:
                assert processes[0].returncode == -signal.SIGKILL
            assert not invocation._process_group_exists(processes[0])
        finally:
            control.request_cancel()
            if worker_pidfd is not None:
                os.close(worker_pidfd)
            if worker_proc_fd is not None:
                os.close(worker_proc_fd)


@pytest.mark.skipif(os.name != "posix", reason="POSIX worker process groups required")
def test_cleanup_stops_residual_child_process(tmp_path):
    # Exercise the same cleanup helpers with an actual descendant. Ordinary
    # macOS containment denies worker forking before it can create this case.
    child_ready = tmp_path / "child-ready"
    script = (
        "import os, signal, sys, time\n"
        "from pathlib import Path\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        " signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        " Path(sys.argv[1]).write_text('ready')\n"
        " while True: time.sleep(0.05)\n"
        "else:\n"
        " while True: time.sleep(0.05)\n"
    )
    process = subprocess.Popen(
        (sys.executable, "-c", script, str(child_ready)),
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    cleanup_verified = False
    try:
        deadline = time.monotonic() + 5
        while not child_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert child_ready.exists()
        invocation._terminate_and_reap_process(process)
        assert invocation._terminate_residual_process_group(process)
        assert not invocation._process_group_exists(process)
        cleanup_verified = True
    finally:
        # After verified exit, the OS can reuse the process-group ID. Only
        # retry cleanup when the test did not already verify its completion.
        if not cleanup_verified:
            invocation._terminate_and_reap_process(process)
            invocation._terminate_residual_process_group(process)

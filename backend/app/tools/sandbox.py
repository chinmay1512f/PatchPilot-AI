"""Execution worker for untrusted repository code.

Backends (selected per job, reported to the user):

* ``docker``  – preferred. No network, all capabilities dropped, read-only root, pids/memory/CPU
  limits, non-root user, only a disposable workspace copy mounted.
* ``local``   – restricted subprocess for machines without Docker. Windows Job Object (memory cap,
  process cap, UI restrictions, kill-on-close) or POSIX rlimits, wall-clock timeout, scrubbed
  environment with no credentials, best-effort socket blocking. This is NOT a security boundary,
  so it is only used when the user explicitly marks the repository as trusted for that job.
* ``blocked`` – nothing is executed; callers record the stage as blocked with the reason.

The API process never imports or executes repository code itself.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings
from ..ingest.secrets import redact

BOOT_SCRIPT = r'''
"""PatchPilot sandbox bootstrap: best-effort network block, then run the requested tool."""
import os, socket, sys

_LOCAL = {"127.0.0.1", "::1", "localhost", "0.0.0.0", None, ""}

def _host(address):
    return address[0] if isinstance(address, tuple) and address else address

def _deny(host):
    raise PermissionError(f"PatchPilot sandbox: outbound network access is disabled (attempted {host!r})")

_connect, _connect_ex, _gai = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

def connect(self, address):
    h = _host(address)
    if getattr(socket, "AF_UNIX", None) == self.family or h in _LOCAL:
        return _connect(self, address)
    _deny(h)

def connect_ex(self, address):
    h = _host(address)
    if getattr(socket, "AF_UNIX", None) == self.family or h in _LOCAL:
        return _connect_ex(self, address)
    _deny(h)

def getaddrinfo(host, *args, **kwargs):
    if host in _LOCAL:
        return _gai(host, *args, **kwargs)
    _deny(host)

socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, getaddrinfo

here = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != here]
sys.path.insert(0, os.getcwd())

# --- Inert stand-ins for third-party packages that are NOT installed -------------------------
# PatchPilot never installs a repository's dependencies. So that the repository's own pure logic
# can still be imported and tested, a missing third-party module listed in stubs.json is replaced
# by an inert stub. The finder sits LAST on sys.meta_path, so anything that is really installed
# is always used. Which modules were stubbed is written to stubbed.json and shown in the report.
import importlib.abc, importlib.machinery, json, types

def _load_stub_names():
    try:
        with open(os.path.join(here, "stubs.json"), encoding="utf-8") as fh:
            return set(json.load(fh))
    except (OSError, ValueError):
        return set()

_STUB_NAMES = _load_stub_names()
_STUBBED = set()

class _StubMeta(type):
    def __getattr__(cls, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _stub_class(f"{cls.__name__}.{name}")
    def __iter__(cls):
        return iter(())
    def __getitem__(cls, item):
        return cls

class _Stub(metaclass=_StubMeta):
    """Stand-in for anything from a missing package: constructible, callable, subclassable."""
    def __init__(self, *args, **kwargs):
        pass
    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _stub_class(f"{type(self).__name__}.{name}")()
    def __call__(self, *args, **kwargs):
        if len(args) == 1 and not kwargs and callable(args[0]) and not isinstance(args[0], _Stub):
            return args[0]  # used as a decorator (e.g. @app.route(...)): keep the real function
        return _stub_class(type(self).__name__ + "()")()
    def __iter__(self): return iter(())
    def __len__(self): return 0
    def __getitem__(self, key): return _stub_class("item")()
    def __setitem__(self, key, value): pass
    def __enter__(self): return self
    def __exit__(self, *exc): return False
    def __repr__(self): return f"<PatchPilot stub {type(self).__name__}>"

def _stub_class(name):
    return _StubMeta(name, (_Stub,), {})

class _StubModule(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _stub_class(f"{self.__name__}.{name}")

class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return _StubModule(spec.name)
    def exec_module(self, module):
        module.__path__ = []
        module.__all__ = []
        module.__patchpilot_stub__ = True
        _STUBBED.add(module.__name__.split(".")[0])

class _StubFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in _STUB_NAMES:
            return importlib.machinery.ModuleSpec(fullname, _StubLoader(), is_package=True)
        return None

if _STUB_NAMES:
    sys.meta_path.append(_StubFinder())

def _write_stubbed():
    try:
        with open(os.path.join(here, "stubbed.json"), "w", encoding="utf-8") as fh:
            json.dump(sorted(_STUBBED), fh)
    except OSError:
        pass

if __name__ == "__main__":
    tool, args = sys.argv[1], sys.argv[2:]
    import atexit
    atexit.register(_write_stubbed)
    if tool == "pytest":
        import pytest
        sys.exit(pytest.main(args))
    sys.exit(f"unknown tool {tool!r}")
'''


@dataclass
class ExecResult:
    backend: str
    command: str
    exit_code: int | None
    output: str
    duration: float
    timed_out: bool = False
    blocked: bool = False
    blocked_reason: str | None = None


class Backend:
    name = "base"
    detail = ""

    def run_python_tool(self, workdir: Path, tool: str, args: list[str], timeout: int) -> ExecResult:
        raise NotImplementedError

    @staticmethod
    def prepare(workdir: Path) -> None:
        pp = workdir / ".patchpilot"
        pp.mkdir(exist_ok=True)
        (pp / "sandbox_boot.py").write_text(BOOT_SCRIPT, encoding="utf-8")
        for d in ("tmp", "home"):
            (pp / d).mkdir(exist_ok=True)


class BlockedBackend(Backend):
    name = "blocked"

    def __init__(self, reason: str):
        self.detail = reason

    def run_python_tool(self, workdir, tool, args, timeout):
        return ExecResult(self.name, f"{tool} {' '.join(args)}", None, "", 0.0, blocked=True, blocked_reason=self.detail)


# --------------------------------------------------------------------------- docker


class DockerBackend(Backend):
    name = "docker"

    def __init__(self, settings: Settings):
        self.s = settings
        self.detail = (
            f"Docker image {settings.docker_image}: --network none, --cap-drop ALL, read-only root, "
            f"{settings.sandbox_memory_mb} MB memory, pids limit {settings.sandbox_max_processes * 8}"
        )

    @staticmethod
    def available(image: str) -> tuple[bool, str]:
        if not shutil.which("docker"):
            return False, "Docker CLI not found"
        try:
            r = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=15)
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"Docker not responding: {e}"
        if r.returncode != 0:
            return False, f"Sandbox image {image} not built (see sandbox/Dockerfile)"
        return True, "ok"

    def run_python_tool(self, workdir, tool, args, timeout):
        self.prepare(workdir)
        cmd = [
            "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", "/tmp:rw,size=256m", "--memory", f"{self.s.sandbox_memory_mb}m",
            "--cpus", "1", "--pids-limit", str(self.s.sandbox_max_processes * 8),
            "--user", "1000:1000", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
            "-v", f"{workdir.resolve()}:/work:rw", "-w", "/work", self.s.docker_image,
            "python", "-E", "-s", "/work/.patchpilot/sandbox_boot.py", tool, *args,
        ]
        return _run(self.name, cmd, workdir, None, timeout, display=f"docker run … python -m {tool} {' '.join(args)}")


# --------------------------------------------------------------------------- local restricted


class LocalRestrictedBackend(Backend):
    name = "local"

    def __init__(self, settings: Settings):
        self.s = settings
        limits = f"{settings.sandbox_memory_mb} MB/process, max {settings.sandbox_max_processes} processes, {settings.sandbox_timeout_seconds}s timeout"
        if os.name == "nt":
            self.detail = f"Windows Job Object ({limits}), scrubbed env, network blocked in-process (best effort). Not a hard security boundary."
        else:
            who = f"separate unprivileged user (uid {settings.sandbox_uid}), " if settings.sandbox_uid else ""
            self.detail = f"POSIX rlimits ({limits}), {who}scrubbed env, network blocked in-process (best effort). Not a hard security boundary."

    def _env(self, workdir: Path) -> dict[str, str]:
        pp = workdir / ".patchpilot"
        tmp, home = str(pp / "tmp"), str(pp / "home")
        dead_proxy = "http://127.0.0.1:9"
        env = {
            "PATH": str(Path(sys.executable).parent),
            "TEMP": tmp, "TMP": tmp, "TMPDIR": tmp, "HOME": home, "USERPROFILE": home,
            "APPDATA": home, "LOCALAPPDATA": home,
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "PYTHONHASHSEED": "0",
            "PATCHPILOT_SANDBOX": "1",
            "HTTP_PROXY": dead_proxy, "HTTPS_PROXY": dead_proxy, "http_proxy": dead_proxy, "https_proxy": dead_proxy,
            "NO_COLOR": "1",
        }
        if os.name == "nt":
            sysroot = os.environ.get("SYSTEMROOT", r"C:\Windows")
            env["SYSTEMROOT"] = sysroot
            env["PATH"] += os.pathsep + str(Path(sysroot) / "System32")
        else:
            env["PATH"] += os.pathsep + "/usr/bin:/bin"
        return env  # note: no ANTHROPIC_API_KEY, no cloud credentials, no SSH agent

    def run_python_tool(self, workdir, tool, args, timeout):
        self.prepare(workdir)
        display = f"python -m {tool} {' '.join(args)}"
        if self.s.sandbox_uid and os.name != "nt":
            if os.geteuid() != 0:  # fail closed: never fall back to running as the server's own user
                reason = ("PATCHPILOT_SANDBOX_UID is set but the server is not running as root, so it cannot switch to "
                          "the sandbox user. Untrusted code was not executed.")
                return ExecResult(self.name, display, None, "", 0.0, blocked=True, blocked_reason=reason)
            hand_over(workdir, self.s.sandbox_uid, self.s.data_dir)
        cmd = [sys.executable, "-E", "-s", str(workdir / ".patchpilot" / "sandbox_boot.py"), tool, *args]
        return _run(self.name, cmd, workdir, self._env(workdir), timeout, settings=self.s, display=display)


def lock_down_data_dir(settings: Settings) -> None:
    """With a sandbox user configured (POSIX, server running as root): keep the database, uploads and
    other jobs private. Directories stay traversable (0711) so the sandbox user can reach the one work
    directory it is given, but it cannot list them or read files it does not own."""
    for d in (settings.data_dir, settings.workspaces_dir):
        os.chmod(d, 0o711)
    os.chmod(settings.recordings_dir, 0o700)
    for f in settings.data_dir.glob("patchpilot.db*"):
        os.chmod(f, 0o600)


def hand_over(workdir: Path, uid: int, data_dir: Path) -> None:
    """Give one disposable work directory to the sandbox user: parents traversable, the directory
    itself owned by that user, nothing else."""
    root = data_dir.resolve()
    p = workdir.resolve().parent
    while p != root and root in p.parents:
        os.chmod(p, 0o711)
        p = p.parent
    for dirpath, dirnames, filenames in os.walk(workdir):
        os.lchown(dirpath, uid, uid)
        for name in dirnames + filenames:
            os.lchown(os.path.join(dirpath, name), uid, uid)


def _run(name, cmd, cwd, env, timeout, settings: Settings | None = None, display: str = "") -> ExecResult:
    start = time.monotonic()
    timed_out = False
    if name == "local" and os.name == "nt":
        code, out, timed_out = _run_windows_job(cmd, cwd, env, timeout, settings)
    else:
        kwargs: dict = {}
        if name == "local" and os.name != "nt":
            kwargs["preexec_fn"] = _posix_limits(settings)
            kwargs["start_new_session"] = True
        try:
            p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kwargs)
        except (OSError, subprocess.SubprocessError) as e:  # SubprocessError: preexec_fn failed (e.g. could not drop privileges)
            return ExecResult(name, display, None, f"failed to start: {e}", 0.0, blocked=True, blocked_reason=str(e))
        try:
            raw, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if name == "local" and os.name != "nt":
                import signal
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            p.kill()
            raw, _ = p.communicate()
        code, out = p.returncode, raw.decode("utf-8", "replace")
    out = redact(out)[0]
    return ExecResult(name, display or " ".join(cmd), code, out, round(time.monotonic() - start, 2), timed_out=timed_out)


def _posix_limits(settings: Settings | None):
    def apply():  # runs in the child before exec
        import resource
        mem = (settings.sandbox_memory_mb if settings else 1024) * 1024 * 1024
        nproc = settings.sandbox_max_processes if settings else 16
        for lim, val in ((resource.RLIMIT_AS, mem), (resource.RLIMIT_NPROC, nproc * 4), (resource.RLIMIT_FSIZE, 200 * 1024 * 1024), (resource.RLIMIT_CORE, 0)):
            try:
                resource.setrlimit(lim, (val, val))
            except (ValueError, OSError):
                pass
        uid = settings.sandbox_uid if settings else 0
        if uid:  # drop to the unprivileged sandbox user; any failure aborts the start (fail closed)
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
            if os.getuid() != uid or os.geteuid() != uid:
                raise OSError("could not drop privileges to the sandbox user")
    return apply


# --------------------------------------------------------------------------- Windows Job Object

def _run_windows_job(cmd, cwd, env, timeout, settings: Settings | None):
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC), ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class UI(ctypes.Structure):
        _fields_ = [("UIRestrictionsClass", wintypes.DWORD)]

    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]

    mem_mb = settings.sandbox_memory_mb if settings else 1024
    nproc = settings.sandbox_max_processes if settings else 16

    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    try:
        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x100 | 0x8 | 0x2000 | 0x400  # PROCESS_MEMORY | ACTIVE_PROCESS | KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION
        info.BasicLimitInformation.ActiveProcessLimit = nproc
        info.ProcessMemoryLimit = mem_mb * 1024 * 1024
        if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject(limits) failed")
        ui = UI(0xFF)  # no clipboard, desktop switching, global atoms, display/system settings, logoff
        k32.SetInformationJobObject(job, 4, ctypes.byref(ui), ctypes.sizeof(ui))

        flags = 0x00000004 | 0x08000000 | 0x00000200  # CREATE_SUSPENDED | CREATE_NO_WINDOW | NEW_PROCESS_GROUP
        p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, creationflags=flags)
        handle = int(p._handle)  # type: ignore[attr-defined]
        if not k32.AssignProcessToJobObject(job, handle):
            err = ctypes.get_last_error()
            p.kill()
            p.communicate()
            raise OSError(err, "AssignProcessToJobObject failed; refusing to run unconfined")
        ntdll.NtResumeProcess(handle)
        timed_out = False
        try:
            raw, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            k32.TerminateJobObject(job, 1)
            raw, _ = p.communicate()
        return p.returncode, raw.decode("utf-8", "replace"), timed_out
    finally:
        k32.CloseHandle(job)  # KILL_ON_JOB_CLOSE reaps any stragglers


# --------------------------------------------------------------------------- selection


def select_backend(settings: Settings, allow_local: bool) -> Backend:
    pref = settings.execution_backend
    if pref == "disabled":
        return BlockedBackend("Code execution is disabled by configuration (PATCHPILOT_EXECUTION_BACKEND=disabled).")
    docker_reason = ""
    if pref in ("auto", "docker"):
        ok, docker_reason = DockerBackend.available(settings.docker_image)
        if ok:
            return DockerBackend(settings)
        if pref == "docker":
            return BlockedBackend(f"Docker sandbox required but unavailable: {docker_reason}.")
    if allow_local:
        return LocalRestrictedBackend(settings)
    return BlockedBackend(
        f"No isolated sandbox available ({docker_reason or 'Docker not selected'}). Untrusted code was not executed. "
        "Install Docker and build the sandbox image, or explicitly mark this repository as trusted to allow "
        "restricted local execution."
    )

"""Static suspicious-behaviour detection (defensive, read-only).

These rules flag *patterns* associated with malicious code. A match is never reported as
confirmed malware: legitimate software also uses subprocesses, networking and file deletion.
Each finding explains what was seen so a human (and Claude's triage) can judge intent.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from ..ingest.indexer import RepoIndex
from ..ingest.secrets import redact

SENSITIVE_PATHS = re.compile(
    r"(\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.docker[/\\]config\.json|\.npmrc|\.pypirc|\.netrc|"
    r"Login Data|Cookies\b|Local State|wallet\.dat|keychain|/etc/shadow|/etc/passwd|\.kube[/\\]config|\.git-credentials)",
    re.I,
)
MINING = re.compile(r"(stratum\+tcp|stratum\+ssl|xmrig|cryptonight|minergate|nicehash|coinhive)", re.I)
SHELL_DOWNLOAD_EXEC = re.compile(r"(curl|wget|iwr|Invoke-WebRequest)[^\n|;]*\|\s*(sh|bash|zsh|python\d?|iex|powershell)", re.I)
REVERSE_SHELL = re.compile(r"(/dev/tcp/|nc\s+(-e|-c)\s|ncat\s.*-e\s|bash\s+-i\s*>&|socat\s.*exec:)", re.I)
DESTRUCTIVE_SHELL = re.compile(r"rm\s+-rf\s+(/|~|\$HOME|/\*)(\s|$)|del\s+/[sqf].*\s+[A-Z]:\\|format\s+[A-Z]:", re.I)
LONG_B64 = re.compile(r"['\"]([A-Za-z0-9+/]{200,}={0,2})['\"]")

DECODERS = {"b64decode", "b32decode", "a85decode", "b85decode", "decompress", "unhexlify", "fromhex", "loads", "rot13", "decode"}
NET_MODULES = {"socket", "requests", "urllib", "urllib3", "httpx", "http", "aiohttp", "ftplib", "smtplib", "paramiko"}


@dataclass
class Suspicion:
    rule_id: str
    title: str
    severity: str
    confidence: str
    file_path: str
    line: int
    snippet: str
    description: str
    tags: list[str] = field(default_factory=list)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _contains_call(node: ast.AST, names: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _call_name(sub.func).split(".")[-1] in names:
            return True
    return False


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, path: str, lines: list[str]):
        self.path, self.lines = path, lines
        self.out: list[Suspicion] = []
        self.imports: set[str] = set()
        self.env_bulk_lines: list[int] = []
        self.func_stack: list[ast.AST] = []

    def snip(self, line: int) -> str:
        return redact(self.lines[line - 1].strip()[:240])[0] if 0 < line <= len(self.lines) else ""

    def add(self, node, rule, title, sev, conf, desc, tags=()):
        line = getattr(node, "lineno", 1)
        self.out.append(Suspicion(rule, title, sev, conf, self.path, line, self.snip(line), desc, list(tags)))

    def visit_Import(self, node):
        for a in node.names:
            self.imports.add(a.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = _call_name(node.func)
        short = name.split(".")[-1]
        args = node.args
        if short in ("exec", "eval", "compile") and name in ("exec", "eval", "compile", "builtins.exec", "builtins.eval"):
            if args and _contains_call(args[0], DECODERS):
                self.add(node, "obfuscated-exec", "Execution of decoded/obfuscated data", "high", "high",
                         f"`{short}` is called on the result of a decoding function. This is a common way to hide a payload from reviewers.",
                         ["obfuscation", "code-execution"])
            elif args and not isinstance(args[0], ast.Constant):
                self.add(node, "dynamic-exec", f"Dynamic `{short}` of non-constant input", "medium", "medium",
                         f"`{short}` executes a value computed at runtime. If any part comes from users, files or the network it allows arbitrary code execution.",
                         ["code-execution"])
        if name in ("marshal.loads",) or (short == "loads" and name.startswith("marshal")):
            self.add(node, "marshal-loads", "Deserialising code objects with marshal", "medium", "low",
                     "marshal can carry compiled bytecode; combined with exec it is used to hide payloads.", ["obfuscation"])
        if short in ("system", "popen") and name.startswith("os.") or name in ("subprocess.getoutput", "subprocess.getstatusoutput"):
            self.add(node, "shell-exec", "Shell command execution", "medium", "low",
                     f"`{name}` runs a shell command. Often legitimate; dangerous if the command includes untrusted input.", ["process"])
        if name.startswith("subprocess.") or short in ("Popen", "run", "call", "check_output", "check_call"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.add(node, "subprocess-shell", "subprocess with shell=True", "medium", "low",
                             "Commands run through a shell; string interpolation here enables command injection.", ["process"])
        if name in ("os.dup2",) and any("fileno" in ast.unparse(a) for a in args):
            self.add(node, "reverse-shell", "Socket file descriptor duplicated onto stdio", "critical", "high",
                     "`os.dup2(sock.fileno(), …)` redirects a process's stdin/stdout to a network socket — the classic reverse-shell technique.",
                     ["remote-access"])
        if short in ("rmtree",) or name in ("os.remove", "os.unlink"):
            target = ast.unparse(args[0]) if args else ""
            if re.search(r"expanduser|Path\.home|HOME|USERPROFILE|['\"](/|~|C:\\\\)['\"]", target):
                self.add(node, "destructive-home", "Deletion targeting the home or root directory", "high", "medium",
                         f"Deletes `{target[:80]}` which resolves to a user/home or root location.", ["destructive"])
        if name in ("dict", "json.dumps", "str") and args and ast.unparse(args[0]) in ("os.environ",):
            self.env_bulk_lines.append(node.lineno)
        if name == "os.environ.copy":
            self.env_bulk_lines.append(node.lineno)
        if short in ("urlretrieve",):
            self.add(node, "download-file", "File downloaded at runtime", "low", "low", "Downloads a remote file.", ["network"])
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            v = node.value
            if SENSITIVE_PATHS.search(v):
                self.add(node, "credential-path", "Reference to credential/secret storage location", "high", "medium",
                         f"String references a location that stores credentials ({SENSITIVE_PATHS.search(v).group(0)}). Reading it is typical of credential-stealing code.",
                         ["credential-access"])
            if MINING.search(v):
                self.add(node, "cryptomining", "Cryptocurrency-mining indicator", "high", "medium",
                         f"Contains mining-related identifier `{MINING.search(v).group(0)}`.", ["cryptomining"])
            if SHELL_DOWNLOAD_EXEC.search(v):
                self.add(node, "download-exec", "Download piped directly into an interpreter", "high", "high",
                         "A command downloads remote content and executes it without verification.", ["download-execute"])
            if REVERSE_SHELL.search(v):
                self.add(node, "reverse-shell-cmd", "Reverse-shell command string", "critical", "high",
                         "Command string matches a known reverse-shell construction.", ["remote-access"])
            if DESTRUCTIVE_SHELL.search(v):
                self.add(node, "destructive-cmd", "Destructive filesystem command", "high", "medium",
                         "Command string recursively deletes a root/home location or formats a drive.", ["destructive"])
            if len(v) >= 200 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", v):
                self.add(node, "encoded-blob", "Large encoded blob embedded in source", "low", "low",
                         f"A {len(v)}-character base64-like string is embedded in code. Could be data or a hidden payload.", ["obfuscation"])


def scan_python(path: str, text: str) -> list[Suspicion]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    v = _PyVisitor(path, lines)
    v.visit(tree)
    out = v.out
    uses_net = bool(v.imports & NET_MODULES)
    if v.env_bulk_lines and uses_net:
        ln = v.env_bulk_lines[0]
        out.append(Suspicion("env-exfiltration", "Bulk environment capture in a module with network access", "high", "medium", path, ln,
                             v.snip(ln), "The whole environment (which often contains API keys and tokens) is collected in a module that also imports networking libraries. Check whether it is transmitted.",
                             ["exfiltration", "credential-access"]))
    has_download = any(s.rule_id == "download-file" for s in out) or bool(re.search(r"(requests|httpx|urllib\.request)\.(get|urlopen)", text))
    has_exec = any(s.rule_id in ("dynamic-exec", "obfuscated-exec", "shell-exec", "subprocess-shell") for s in out)
    if has_download and has_exec:
        first = next(s for s in out if s.rule_id in ("dynamic-exec", "obfuscated-exec", "shell-exec", "subprocess-shell"))
        out.append(Suspicion("download-and-execute", "Module both downloads remote content and executes code", "high", "low", path, first.line,
                             first.snippet, "This module fetches data from the network and also executes code or commands dynamically. Verify the executed content is not the downloaded data.",
                             ["download-execute"]))
    if path.endswith("setup.py") and ("cmdclass" in text) and (uses_net or has_exec):
        out.append(Suspicion("install-hook", "setup.py install hook performs network or command execution", "high", "medium", path, 1,
                             "", "setup.py overrides install commands and contains networking or execution code that would run during `pip install`.",
                             ["install-hook"]))
    return out


def scan_text(path: str, text: str) -> list[Suspicion]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for rx, rule, title, sev, conf in (
            (SHELL_DOWNLOAD_EXEC, "download-exec", "Download piped directly into an interpreter", "high", "high"),
            (REVERSE_SHELL, "reverse-shell-cmd", "Reverse-shell command", "critical", "high"),
            (DESTRUCTIVE_SHELL, "destructive-cmd", "Destructive filesystem command", "high", "medium"),
            (MINING, "cryptomining", "Cryptocurrency-mining indicator", "high", "medium"),
        ):
            if rx.search(line):
                out.append(Suspicion(rule, title, sev, conf, path, i, redact(line.strip()[:240])[0], f"Line matches pattern for: {title.lower()}.", []))
    return out


def scan_repo(index: RepoIndex) -> list[Suspicion]:
    findings: list[Suspicion] = []
    for f in index.files.values():
        if f.text is None:
            continue
        if f.path.endswith(".py"):
            findings += scan_python(f.path, f.text)
        elif f.language in ("Shell", "PowerShell", "Batch", "JavaScript", "TypeScript", "Dockerfile") or f.path.endswith("package.json"):
            findings += scan_text(f.path, f.text)
    for sf in index.facts.special_files:
        if "install" in sf.reason and "npm" in sf.reason:
            sev = "high" if SHELL_DOWNLOAD_EXEC.search(sf.reason) or re.search(r"curl|wget|node -e|powershell|eval", sf.reason) else "medium"
            findings.append(Suspicion("npm-install-script", "npm lifecycle script runs on install", sev, "medium", sf.path, 1, sf.reason[:240],
                                      "Lifecycle scripts execute automatically during `npm install` and are a common supply-chain attack vector.", ["install-hook"]))
    from .malware import extra_checks  # malware-indicator rules (keylogging, exfiltration, persistence, ...)
    findings += extra_checks(index)
    return findings

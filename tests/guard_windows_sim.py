"""Simulates the guard hook with Windows path rules (ntpath), so Windows behaviour
is checked on any OS. Run by tests/selftest.sh; exits 1 on any failure."""
import importlib.util, io, json, ntpath, os, sys, types, tempfile, pathlib
os.environ["USERPROFILE"] = r"C:\Users\tashe"
os.environ["CLAUDE_PROJECT_DIR"] = "/c/code/unraid-audit"          # Git Bash style
spec = importlib.util.spec_from_file_location("guard", sys.argv[1] if len(sys.argv) > 1 else ".claude/hooks/guard.py"); g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
shim = types.SimpleNamespace(path=ntpath, name="nt", environ=os.environ, getcwd=lambda: r"C:\code\unraid-audit", sep="\\")
g.os = shim; g.IS_WINDOWS = True
g.HOME = ntpath.expanduser("~")
g.PROTECTED_READ = [p for p in g.PROTECTED_READ if p.startswith("/")] + [ntpath.join(g.HOME, ".ssh")]
g.backup_age_hours = lambda: 0.0
def run(tool, ti, cwd="C:\\code\\unraid-audit"):
    sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(json.dumps({"tool_name":tool,"tool_input":ti,"cwd":cwd}).encode()))
    out = io.StringIO(); so = sys.stdout; sys.stdout = out; err = io.StringIO(); se = sys.stderr; sys.stderr = err
    try: g.main(); rc = 0
    except SystemExit as e: rc = e.code
    finally: sys.stdout, sys.stderr = so, se
    return 2 if rc == 2 else ("ask" if '"ask"' in out.getvalue() else 0)
cases = [
 ("Bash", {"command":"ssh unraid-audit help"}, 0),
 ("Bash", {"command":"ssh unraid-audit docker-restart plex"}, 0),
 ("Bash", {"command":"ssh unraid-audit docker-remove plex"}, "ask"),
 ("Bash", {"command":"ssh unraid-audit ls /mnt/user"}, 2),
 ("Bash", {"command":"ls -la"}, 0),
 ("Bash", {"command":"ls /mnt/user"}, 2),
 ("Bash", {"command":"cat /c/Users/tashe/.ssh/unraid_audit"}, 2),
 ("Bash", {"command":"cat C:/Users/tashe/.ssh/config"}, 2),
 ("Bash", {"command":"powershell -c dir"}, 2),
 ("Bash", {"command":"cmd.exe /c dir"}, 2),
 ("Bash", {"command":"grep -i error notes/x.txt"}, 0),
 ("Read", {"file_path": r"C:\code\unraid-audit\plan.md"}, 0),
 ("Read", {"file_path": "/c/code/unraid-audit/plan.md"}, 0),
 ("Read", {"file_path": r"C:\Users\tashe\.ssh\unraid_audit"}, 2),
 ("Read", {"file_path": "/c/Users/tashe/.ssh/unraid_audit"}, 2),
 ("Read", {"file_path": "/mnt/user/photos/a.jpg"}, 2),
 ("Read", {"file_path": "/boot/config/shadow"}, 2),
 ("Grep", {"pattern":"x","path":"/mnt/disk1"}, 2),
 ("Glob", {"pattern":"/mnt/**/*.jpg"}, 2),
 ("Write", {"file_path": r"C:\code\unraid-audit\notes\report.md"}, 0),
 ("Write", {"file_path": "/c/code/unraid-audit/notes/report.md"}, 0),
 ("Write", {"file_path": r"c:\CODE\Unraid-Audit\notes\r.md"}, 0),
 ("Write", {"file_path": r"C:\code\unraid-audit\.claude\settings.json"}, 2),
 ("Edit",  {"file_path": "/c/code/unraid-audit/.claude/hooks/guard.py"}, 2),
 ("Write", {"file_path": r"C:\code\unraid-audit\.CLAUDE\backup-confirmed"}, 2),
 ("Write", {"file_path": r"C:\Windows\System32\drivers\etc\hosts"}, 2),
 ("Write", {"file_path": r"D:\elsewhere\x.txt"}, 2),
 ("Write", {"file_path": r"C:\code\unraid-audit\..\other\x.txt"}, 2),
 ("PowerShell", {"command":"Get-ChildItem"}, 2),
]
bad = 0
for tool, ti, want in cases:
    got = run(tool, ti)
    if got != want: bad += 1; print("FAIL", tool, ti, "want", want, "got", got)
print(f"windows-sim: {len(cases)-bad}/{len(cases)} ok")
sys.exit(1 if bad else 0)

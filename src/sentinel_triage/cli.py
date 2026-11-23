"""Command-line interface.

  sentinel-triage scan TARGET [--provider mock|anthropic|openai]
                              [--model NAME] [--no-llm]
                              [--format md|json|both] [--out DIR]
  sentinel-triage demo          # scan the bundled vulnerable fixture app
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .guards import GuardError, resolve_target
from .providers import ProviderError, get_provider
from .report import to_json, to_markdown
from .triager import collect_findings, triage_with_llm

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "vulnerable_app")


def _write_outputs(result, fmt: str, out_dir: str) -> list:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    if fmt in ("md", "both"):
        path = os.path.join(out_dir, "triage-report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(result))
        written.append(path)
    if fmt in ("json", "both"):
        path = os.path.join(out_dir, "triage-report.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_json(result))
        written.append(path)
    return written


def run_scan(target: str, provider_name: str, model, no_llm: bool,
             fmt: str, out_dir: str, sarif_files=None, baseline=None, use_osv=False,
             investigate=False, investigate_with_llm=False, investigate_max=10) -> int:
    from .importers import SarifImportError

    try:
        resolved = resolve_target(target)
    except GuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        result = collect_findings(resolved, sarif_files=sarif_files, baseline_path=baseline,
                                  use_osv=use_osv)
    except SarifImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    provider = None
    if not no_llm:
        try:
            provider = get_provider(provider_name, model=model)
        except ProviderError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        result = triage_with_llm(result, provider)
        if not result.llm_used and "_error" in result.triage_notes:
            print(f"warning: {result.triage_notes['_error']['detail']}", file=sys.stderr)

    if investigate:
        from .triager import run_investigations
        try:
            result = run_investigations(
                result, provider=provider,
                use_llm_planner=investigate_with_llm,
                max_findings=investigate_max,
            )
        except ProviderError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    written = _write_outputs(result, fmt, out_dir)
    counts = result.severity_counts()
    total = sum(counts.values())
    suppressed_note = f", {result.baseline_suppressed} suppressed by baseline" if result.baseline_suppressed else ""
    print(f"scanned {result.files_scanned} files, "
          f"{total} unique findings ({result.duplicates_removed} duplicates removed{suppressed_note})")
    print("by severity: " + ", ".join(f"{k}={v}" for k, v in counts.items() if v))
    if result.llm_used:
        tag = " [MOCK - offline template, not a real model]" if result.llm_is_mock else ""
        print(f"llm triage: {result.llm_provider}{tag}")
    if result.investigations:
        verdicts = {}
        for inv in result.investigations.values():
            verdicts[inv["verdict"]] = verdicts.get(inv["verdict"], 0) + 1
        print(f"investigations: {len(result.investigations)} "
              f"({result.investigations_planner} planner): "
              + ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items())))
    for path in written:
        print(f"wrote {path}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-triage",
        description="Defensive security triage agent: scan, deduplicate, rank, explain.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a directory you own or are authorized to test")
    scan.add_argument("target", help="directory to scan (read-only)")
    scan.add_argument("--provider", default="mock", choices=["mock", "anthropic", "openai"],
                      help="LLM provider for triage notes (default: mock, fully offline)")
    scan.add_argument("--model", default=None, help="override the provider's default model")
    scan.add_argument("--no-llm", action="store_true", help="deterministic ranking only")
    scan.add_argument("--format", default="both", choices=["md", "json", "both"])
    scan.add_argument("--out", default="sentinel-output", help="output directory")
    scan.add_argument("--sarif", action="append", default=[], metavar="FILE",
                      help="also triage findings from a SARIF file (Semgrep/CodeQL/Trivy); repeatable")
    scan.add_argument("--baseline", default=None, metavar="FILE",
                      help="baseline JSON of reviewed finding fingerprints to suppress "
                           "(default: .sentinel-baseline.json in the target)")
    scan.add_argument("--osv", action="store_true",
                      help="also query the public OSV advisory API online (opt-in; no key "
                           "needed). Failure falls back to the built-in offline set with a warning")
    scan.add_argument("--investigate", action="store_true",
                      help="run the bounded investigation loop on the top findings "
                           "(deterministic playbooks by default)")
    scan.add_argument("--investigate-with-llm", action="store_true",
                      help="let a real provider (not mock) choose investigation actions; "
                           "same allowlist, limits and provenance")
    scan.add_argument("--investigate-max", type=int, default=10, metavar="N",
                      help="max findings to investigate (default 10)")

    demo = sub.add_parser("demo", help="scan the bundled synthetic vulnerable app")
    demo.add_argument("--provider", default="mock", choices=["mock", "anthropic", "openai"])
    demo.add_argument("--model", default=None)
    demo.add_argument("--no-llm", action="store_true")
    demo.add_argument("--format", default="both", choices=["md", "json", "both"])
    demo.add_argument("--out", default="sentinel-output")
    demo.add_argument("--sarif", action="append", default=[], metavar="FILE")
    demo.add_argument("--baseline", default=None, metavar="FILE")
    demo.add_argument("--osv", action="store_true")
    demo.add_argument("--investigate", action="store_true")
    demo.add_argument("--investigate-with-llm", action="store_true")
    demo.add_argument("--investigate-max", type=int, default=10, metavar="N")

    scopep = sub.add_parser("scope", help="validate a scope file and test targets against it")
    scopep.add_argument("scope_file", help="scope file (JSON or minimal YAML subset)")
    scopep.add_argument("--check", action="append", default=[], metavar="TARGET",
                        help="test whether TARGET is in scope (repeatable)")

    planp = sub.add_parser("plan", help="build the engagement plan (PTT) for a scoped target")
    planp.add_argument("scope_file", help="scope file (JSON or minimal YAML subset)")
    planp.add_argument("--expand", default=None, metavar="TASK",
                       help="expand a to-do task number into sub-steps")

    reconp = sub.add_parser("recon", help="plan or run safe recon tooling against in-scope targets")
    reconp.add_argument("scope_file", help="scope file (JSON or minimal YAML subset)")
    reconp.add_argument("--target", action="append", default=[], metavar="TARGET",
                        help="limit to these targets (must be in scope; repeatable)")
    reconp.add_argument("--plugin", action="append", default=[], metavar="NAME",
                        help="limit to these plugins (see --list; repeatable)")
    reconp.add_argument("--list", action="store_true", help="list available plugins and exit")
    reconp.add_argument("--execute", action="store_true",
                        help="actually run the planned commands (default: dry-run only)")
    reconp.add_argument("--timeout", type=int, default=120, metavar="SECONDS")

    proxyp = sub.add_parser(
        "proxy", help="run the scope-enforcing egress proxy for manual tooling")
    proxyp.add_argument("scope_file", help="scope file (JSON or minimal YAML subset)")
    proxyp.add_argument("--port", type=int, default=0,
                        help="loopback port to listen on (default: auto)")

    osintp = sub.add_parser("osint", help="print the passive OSINT checklist for a scoped target")
    osintp.add_argument("scope_file", help="scope file (JSON or minimal YAML subset)")
    osintp.add_argument("--subject", default=None, metavar="DOMAIN",
                        help="subject domain (default: first scoped domain)")

    args = parser.parse_args(argv)

    if args.command == "scope":
        return run_scope(args)
    if args.command == "plan":
        return run_plan(args)
    if args.command == "recon":
        return run_recon_cmd(args)
    if args.command == "proxy":
        return run_proxy_cmd(args)
    if args.command == "osint":
        return run_osint(args)

    if args.command == "demo":
        target = os.path.realpath(FIXTURES_DIR)
        if not os.path.isdir(target):
            print("error: the demo needs a source checkout (fixtures are not shipped in the "
                  "installed package); clone the repo or run: sentinel-triage scan TARGET", file=sys.stderr)
            return 2
        print(f"demo: scanning synthetic fixture app at {target}")
        return run_scan(target, args.provider, args.model, args.no_llm, args.format, args.out,
                        sarif_files=args.sarif, baseline=args.baseline, use_osv=args.osv,
                        investigate=args.investigate,
                        investigate_with_llm=args.investigate_with_llm,
                        investigate_max=args.investigate_max)

    return run_scan(args.target, args.provider, args.model, args.no_llm, args.format, args.out,
                    sarif_files=args.sarif, baseline=args.baseline, use_osv=args.osv,
                    investigate=args.investigate,
                    investigate_with_llm=args.investigate_with_llm,
                    investigate_max=args.investigate_max)


def run_proxy_cmd(args) -> int:
    from .egress import EgressProxy
    from .scope import Scope, ScopeError
    try:
        scope = Scope.from_file(args.scope_file)
    except (ScopeError, OSError) as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2
    print("engagement scope loaded; the proxy enforces it on every request.", flush=True)
    print("point tools at it, e.g.: httpx -proxy PROXY_URL / nuclei -proxy PROXY_URL", flush=True)
    try:
        with EgressProxy(scope, port=args.port) as proxy:
            print(f"scope-enforcing egress proxy listening at {proxy.url} "
                  "(127.0.0.1 only, Ctrl-C to stop)", flush=True)
            try:
                import threading
                threading.Event().wait()
            except KeyboardInterrupt:
                pass
    except OSError as exc:
        print(f"could not start proxy: {exc}", file=sys.stderr)
        return 2
    return 0


def run_scope(args) -> int:
    from .scope import Scope, ScopeError
    try:
        scope = Scope.from_file(args.scope_file)
    except (OSError, ScopeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"engagement: {scope.engagement or '(unnamed)'}")
    print(f"domains: {', '.join(scope.domains) or '-'}")
    print(f"networks: {', '.join(str(n) for n in scope.networks) or '-'}")
    print(f"exclusions: {', '.join(scope.excluded_domains + tuple(str(n) for n in scope.excluded_networks)) or '-'}")
    print(f"allow_active: {scope.allow_active}")
    status = 0
    for target in args.check:
        decision = scope.check(target)
        mark = "ALLOW " if decision.allowed else "DENY  "
        print(f"{mark}{target}: {decision.reason}")
        if not decision.allowed:
            status = 1
    return status


def run_plan(args) -> int:
    from .ptree import build_initial_tree, expand_recon_task, render_ptt
    from .scope import Scope, ScopeError
    try:
        scope = Scope.from_file(args.scope_file)
    except (OSError, ScopeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    tree = build_initial_tree(scope)
    if args.expand:
        node = tree.find(args.expand)
        created = expand_recon_task(scope, node)
        print(f"expanded task {args.expand} into {len(created)} sub-steps")
    print(render_ptt(tree))
    return 0


def run_recon_cmd(args) -> int:
    from . import recon
    from .scope import Scope, ScopeError
    if args.list:
        for plugin in recon.REGISTRY:
            print(f"{plugin.name:16s} [{plugin.category}] {plugin.description}")
            print(f"{'':16s}   {plugin.homepage}")
        return 0
    try:
        scope = Scope.from_file(args.scope_file)
    except (OSError, ScopeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    results = recon.run(
        scope,
        targets=args.target or None,
        plugin_names=args.plugin or None,
        execute=args.execute,
        timeout=args.timeout,
    )
    for result in results:
        cmd = " ".join(result.plan.argv)
        if result.ran:
            print(f"RAN     {cmd} (exit {result.returncode})")
            if result.stdout.strip():
                print(result.stdout.rstrip())
        else:
            label = "WOULD " if not args.execute else "SKIP  "
            print(f"{label}{cmd}  # {result.skipped_reason}")
    if not args.execute:
        print("\ndry-run only; pass --execute to run the allowed commands")
    return 0


def run_osint(args) -> int:
    from .osint import build_osint_plan, OsintError
    from .scope import Scope, ScopeError
    try:
        scope = Scope.from_file(args.scope_file)
        items = build_osint_plan(scope, subject=args.subject or "")
    except (OSError, ScopeError, OsintError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for label, value in items:
        print(f"{label}\n  {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

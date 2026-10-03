"""
main.py — CyberPulse Orchestrator
====================================
Entry point for the Autonomous Penetration Testing Swarm.

Usage:
    python main.py --target http://localhost:5000
    python main.py --target http://localhost:5000 --mode full
    python main.py --target http://localhost:5000 --mode recon-only
    python main.py --target http://localhost:5000 --mode exploit-only
    python main.py --target http://localhost:5000 --mode patch-only
    python main.py --target http://localhost:5000 --mode re-exploit --patched-target http://localhost:5001
    python main.py --mode sast-only --sast-path vulnapp        # Semgrep (SAST)
    python main.py --mode dast-only --target http://localhost:5000   # OWASP ZAP (DAST)
    python main.py --target http://localhost:5000 --mode full --with-sast --with-dast
    python main.py --gui                    # web dashboard on http://127.0.0.1:5002

Modes:
    full          Run the complete pipeline: recon → exploit → validate → patch → re-exploit
    recon-only    Only run the Recon Agent
    exploit-only  Run Exploit + Validator (assumes recon_results.json exists)
    patch-only    Run Patching Agent only (assumes validation_report.json exists)
    re-exploit    Re-run Exploit + Validator against the patched target URL
    sast-only     Static analysis with Semgrep (source-level)
    dast-only     Dynamic analysis with OWASP ZAP (running target, needs Docker)

Scanner flags:
    --with-sast         Add SAST before patching + a re-scan of vulnapp_patched/
    --with-dast         Add DAST before patching + a re-scan of the patched target
"""

import argparse
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from agents import ExploitAgent, PatchingAgent, ReconAgent, ValidatorAgent
from agents.dast_agent import DastAgent
from agents.sast_agent import SastAgent

console = Console()

# ─── Phase 5 state files (kept separate so Phase 2/3 results survive) ─────────
REEXPLOIT_FILE = "reexploit_results.json"
REVALIDATION_FILE = "revalidation_report.json"

# ─── SAST / DAST state files (before and after patching) ──────────────────────
SAST_FILE = "sast_report.json"
SAST_PATCHED_FILE = "sast_report_patched.json"
DAST_FILE = "dast_report.json"
DAST_PATCHED_FILE = "dast_report_patched.json"

BANNER = """
 ██████╗ ██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗██╗     ███████╗███████╗
██╔════╝ ╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
██║       ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██║     ███████╗█████╗
██║        ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║     ╚██████╔╝███████╗███████║███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝

  Autonomous Penetration Testing & Vulnerability Exploitation Swarm
  ⚠️  FOR ISOLATED SANDBOX / EDUCATIONAL USE ONLY ⚠️
"""


def print_banner():
    try:
        console.print(Panel(Text(BANNER, style="bold red"), border_style="red"))
    except UnicodeEncodeError:
        # Legacy cp1252 console: fall back to ASCII so --help / startup still works
        console.print(Panel("CyberPulse -- Autonomous Pentesting Swarm\n"
                            "FOR ISOLATED SANDBOX / EDUCATIONAL USE ONLY",
                            border_style="red"))


def _ensure_utf8_console() -> None:
    """
    Legacy Windows consoles default to cp1252, which cannot encode the banner's
    box-drawing characters or the status emoji. Reconfiguring the streams to
    UTF-8 (with replacement) keeps the CLI usable without setting env vars.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass  # e.g. pytest capture objects — nothing to do


def print_phase(phase_num: int, name: str, description: str):
    console.print()
    console.print(Panel(
        f"[bold]Phase {phase_num}:[/bold] {name}\n[dim]{description}[/dim]",
        border_style="cyan"
    ))


def run_full_pipeline(target: str, patched_target: str, timeout: int, port_scan: bool = True,
                      with_sast: bool = False, with_dast: bool = False,
                      sast_path: str = "vulnapp", patch_sast: bool = False):
    results = {}
    start = time.time()

    # ── Phase 1: Recon ────────────────────────────────────────────────────────
    print_phase(1, "Reconnaissance", "Mapping endpoints, fingerprinting stack, cataloging attack vectors")
    recon = ReconAgent(target_url=target, timeout=timeout, port_scan=port_scan)
    results["recon"] = recon.execute()

    # ── Phase 1b: SAST (static, source-level) ─────────────────────────────────
    if with_sast:
        print_phase("1b", "Static Analysis (SAST)", "Scanning source with Semgrep")
        sast = SastAgent(scan_paths=[sast_path], output_file=SAST_FILE)
        results["sast"] = sast.execute()

    # ── Phase 2: Exploit ──────────────────────────────────────────────────────
    print_phase(2, "Exploitation", "Executing payloads against discovered attack vectors")
    exploit = ExploitAgent(target_url=target, timeout=timeout)
    results["exploit"] = exploit.execute()

    # ── Phase 3: Validate ─────────────────────────────────────────────────────
    print_phase(3, "Validation", "Re-verifying potential successes, classifying findings")
    validator = ValidatorAgent(target_url=target, timeout=timeout)
    results["validation"] = validator.execute()

    # ── Phase 3b: DAST (dynamic, running target) ──────────────────────────────
    if with_dast:
        print_phase("3b", "Dynamic Analysis (DAST)", "Scanning the running target with OWASP ZAP")
        dast = DastAgent(target_url=target, output_file=DAST_FILE)
        results["dast"] = dast.execute()

    # ── Phase 4: Patch ────────────────────────────────────────────────────────
    print_phase(4, "Patching", "Reading source code, applying targeted security fixes")
    patcher = PatchingAgent(target_url=target, timeout=timeout, include_sast=patch_sast)
    results["patch"] = patcher.execute()

    # ── Phase 5: Re-Exploit (against patched app) ─────────────────────────────
    if patched_target:
        print_phase(5, "Re-Exploitation Verification",
                    f"Running exploit suite against patched app at {patched_target}")
        # Phase 5 writes its own state files so the original target's findings
        # (exploit_results.json / validation_report.json) are preserved.
        re_exploit = ExploitAgent(target_url=patched_target, timeout=timeout,
                                  output_file=REEXPLOIT_FILE)
        results["re_exploit"] = re_exploit.execute()
        results["re_exploit"]["_note"] = "Against patched app — all should be FAILED"

        re_validate = ValidatorAgent(target_url=patched_target, timeout=timeout,
                                     exploit_file=REEXPLOIT_FILE,
                                     output_file=REVALIDATION_FILE)
        results["re_validation"] = re_validate.execute()

        # ── Phase 5b: SAST/DAST re-scan of the patched app ────────────────────
        # Static proof (Semgrep) + dynamic proof (ZAP) that the fix landed.
        if with_sast:
            print_phase("5b", "SAST Re-Scan (patched source)",
                        "Re-running Semgrep over vulnapp_patched/")
            sast_patched = SastAgent(scan_paths=["vulnapp_patched"],
                                     output_file=SAST_PATCHED_FILE)
            results["sast_patched"] = sast_patched.execute()

        if with_dast:
            print_phase("5c", "DAST Re-Scan (patched target)",
                        f"Re-running OWASP ZAP against {patched_target}")
            dast_patched = DastAgent(target_url=patched_target,
                                     output_file=DAST_PATCHED_FILE)
            results["dast_patched"] = dast_patched.execute()


    elapsed = time.time() - start
    _print_pipeline_summary(results, elapsed)
    return results


def run_recon_only(target: str, timeout: int, port_scan: bool = True):
    print_phase(1, "Reconnaissance Only", f"Target: {target}")
    recon = ReconAgent(target_url=target, timeout=timeout, port_scan=port_scan)
    return recon.execute()


def run_exploit_only(target: str, timeout: int):
    print_phase(2, "Exploit + Validate", f"Target: {target}")
    exploit = ExploitAgent(target_url=target, timeout=timeout)
    exploit.execute()

    print_phase(3, "Validation", "Classifying exploit results")
    validator = ValidatorAgent(target_url=target, timeout=timeout)
    return validator.execute()


def run_patch_only(target: str, timeout: int, patch_sast: bool = False):
    print_phase(4, "Patching Only", f"Target source: vulnapp/")
    patcher = PatchingAgent(target_url=target, timeout=timeout, include_sast=patch_sast)
    return patcher.execute()


def run_sast_only(scan_path: str, output_file: str = SAST_FILE):
    print_phase("SAST", "Static Analysis", f"Scanning {scan_path} with Semgrep")
    return SastAgent(scan_paths=[scan_path], output_file=output_file).execute()


def run_dast_only(target: str, scan_type: str = "baseline",
                  output_file: str = DAST_FILE):
    print_phase("DAST", "Dynamic Analysis", f"Scanning {target} with OWASP ZAP ({scan_type})")
    return DastAgent(target_url=target, scan_type=scan_type, output_file=output_file).execute()


def run_re_exploit(patched_target: str, timeout: int):
    print_phase(5, "Re-Exploitation Verification", f"Patched target: {patched_target}")
    # Own state files: keep the original target's results intact for comparison.
    exploit = ExploitAgent(target_url=patched_target, timeout=timeout,
                           output_file=REEXPLOIT_FILE)
    exploit.execute()

    validator = ValidatorAgent(target_url=patched_target, timeout=timeout,
                               exploit_file=REEXPLOIT_FILE,
                               output_file=REVALIDATION_FILE)
    result = validator.execute()

    if isinstance(result, dict) and "summary" in result:
        confirmed = result["summary"].get("confirmed", 0)
        if confirmed == 0:
            console.print("\n[bold green]✅ All confirmed vulnerabilities are remediated "
                          "(0 confirmed against the patched app).[/bold green]")
        else:
            console.print(f"\n[bold red]⚠️  {confirmed} finding(s) still confirmed against the "
                          "patched app — the patch is incomplete.[/bold red]")
    return result


def _print_pipeline_summary(results: dict, elapsed: float):
    console.rule("[bold white]📊 PIPELINE COMPLETE[/bold white]")

    validation = results.get("validation", {})
    summary = validation.get("summary", {})
    patches = results.get("patch", {}).get("patches_applied", 0)

    console.print(f"\n[bold]⏱  Total time:[/bold] {elapsed:.1f}s")
    console.print(f"[red]💥 Confirmed vulnerabilities:[/red] {summary.get('confirmed', 'N/A')}")
    console.print(f"[green]🩹 Patches applied:[/green] {patches}")

    _print_scanner_summary(results)

    final_report = Path("state/final_report.md")
    if final_report.exists():
        console.print(f"\n[bold green]📄 Final report:[/bold green] {final_report.resolve()}")


def _print_scanner_summary(results: dict) -> None:
    """Show SAST/DAST before-vs-after patching when those phases ran."""
    sast, dast = results.get("sast"), results.get("dast")
    if not isinstance(sast, dict) and not isinstance(dast, dict):
        return

    def _count(report, key):
        if not isinstance(report, dict) or report.get("status") != "complete":
            return None
        if key == "sast":
            return report.get("summary", {}).get("total")
        return report.get("summary", {}).get("total_alerts")

    def _line(label, before, after, unit):
        if before is None:
            return
        if after is None:
            console.print(f"[magenta]{label}:[/magenta] {before} {unit}")
            return
        arrow = "[green]↓[/green]" if after < before else ("[dim]=[/dim]" if after == before else "[red]↑[/red]")
        console.print(f"[magenta]{label}:[/magenta] {before} → {after} {unit} {arrow} (patched)")

    console.print("")
    _line("🔎 SAST findings", _count(sast, "sast"), _count(results.get("sast_patched"), "sast"), "static findings")
    _line("🌐 DAST alerts", _count(dast, "dast"), _count(results.get("dast_patched"), "dast"), "ZAP alerts")


def main():
    _ensure_utf8_console()
    print_banner()

    parser = argparse.ArgumentParser(
        description="CyberPulse — Autonomous Penetration Testing Swarm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target http://localhost:5000
  python main.py --target http://localhost:5000 --mode full --patched-target http://localhost:5001
  python main.py --target http://localhost:5000 --mode recon-only
  python main.py --target http://localhost:5000 --mode exploit-only
  python main.py --target http://localhost:5000 --mode patch-only
        """
    )

    parser.add_argument(
        "--target", "-t",
        default="http://localhost:5000",
        help="Target URL (default: http://localhost:5000)"
    )
    parser.add_argument(
        "--patched-target",
        default=None,
        help="Patched app URL for re-exploitation phase (e.g. http://localhost:5001)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["full", "recon-only", "exploit-only", "patch-only", "re-exploit",
                 "sast-only", "dast-only"],
        default="full",
        help="Pipeline mode (default: full)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--no-port-scan",
        action="store_true",
        help="Skip port scanning during recon phase"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the web dashboard (http://127.0.0.1:5002) instead of running the pipeline"
    )
    parser.add_argument(
        "--gui-host",
        default="127.0.0.1",
        help="Dashboard bind host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--gui-port",
        type=int,
        default=5002,
        help="Dashboard bind port (default: 5002)"
    )
    parser.add_argument(
        "--with-sast",
        action="store_true",
        help="Include Semgrep static analysis (and a re-scan of the patched source)"
    )
    parser.add_argument(
        "--with-dast",
        action="store_true",
        help="Include OWASP ZAP dynamic analysis (and a re-scan of the patched target)"
    )
    parser.add_argument(
        "--sast-path",
        default="vulnapp",
        help="Source path for SAST scans (default: vulnapp)"
    )
    parser.add_argument(
        "--zap-scan-type",
        choices=["baseline", "full"],
        default="baseline",
        help="ZAP scan profile: baseline (passive+spider) or full (active attacks)"
    )
    parser.add_argument(
        "--patch-sast",
        action="store_true",
        help="Also remediate SAST-reported types (default: only exploit-confirmed findings)"
    )

    args = parser.parse_args()

    # ── Web dashboard mode ────────────────────────────────────────────────────
    if args.gui:
        # Imported lazily so the CLI keeps working even without Flask installed.
        from gui.app import create_app

        console.print(f"[bold]Dashboard:[/bold] http://{args.gui_host}:{args.gui_port}")
        console.print("[dim]Terminal output from pipeline runs is preserved and mirrored in the browser.[/dim]\n")
        create_app().run(host=args.gui_host, port=args.gui_port,
                         debug=False, use_reloader=False)
        return

    console.print(f"[bold]Target:[/bold] {args.target}")
    console.print(f"[bold]Mode:[/bold]   {args.mode}")
    console.print()

    try:
        if args.mode == "full":
            run_full_pipeline(args.target, args.patched_target, args.timeout,
                              port_scan=not args.no_port_scan,
                              with_sast=args.with_sast, with_dast=args.with_dast,
                              sast_path=args.sast_path, patch_sast=args.patch_sast)
        elif args.mode == "recon-only":
            run_recon_only(args.target, args.timeout, port_scan=not args.no_port_scan)
        elif args.mode == "sast-only":
            run_sast_only(args.sast_path)
        elif args.mode == "dast-only":
            run_dast_only(args.target, scan_type=args.zap_scan_type)
        elif args.mode == "exploit-only":
            run_exploit_only(args.target, args.timeout)
        elif args.mode == "patch-only":
            run_patch_only(args.target, args.timeout, patch_sast=args.patch_sast)
        elif args.mode == "re-exploit":
            if not args.patched_target:
                console.print("[red]--patched-target is required for re-exploit mode[/red]")
                sys.exit(1)
            run_re_exploit(args.patched_target, args.timeout)

    except KeyboardInterrupt:
        console.print("\n[yellow]Pipeline interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Pipeline error: {e}[/bold red]")
        raise


if __name__ == "__main__":
    main()

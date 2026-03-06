"""
SIEM Log Analyzer — CLI Entry Point
Usage:
    python main.py --log logs/auth.log --format syslog --report reports/
    python main.py --log logs/access.log --format apache --report reports/
    python main.py --demo   # generates synthetic logs and runs full pipeline
"""

import argparse
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from src.analyzer import SIEMPipeline, logger


def generate_demo_logs(output_dir: Path) -> dict[str, Path]:
    """Synthesise realistic syslog and Apache log samples for demo purposes."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Syslog: SSH brute-force simulation ---
    syslog_lines = []
    base_ts = datetime.now(timezone.utc) - timedelta(minutes=5)
    attacker_ip = "185.220.101.42"
    for i in range(12):
        ts = (base_ts + timedelta(seconds=i * 4)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        user = random.choice(["root", "admin", "ubuntu", "ec2-user"])
        port = random.randint(40000, 65535)
        syslog_lines.append(
            f"<38>1 {ts} web-server-01 sshd 1234 - - "
            f"Failed password for {user} from {attacker_ip} port {port} ssh2"
        )

    # sudo off-hours
    ts = (base_ts + timedelta(minutes=3)).replace(hour=23).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    syslog_lines.append(
        f"<38>1 {ts} web-server-01 sudo 5678 - - "
        f"devops : TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/bin/bash"
    )

    syslog_path = output_dir / "auth.log"
    syslog_path.write_text("\n".join(syslog_lines))

    # --- Apache: large file transfer ---
    apache_lines = []
    for _ in range(5):
        ts = (base_ts + timedelta(seconds=random.randint(0, 120))).strftime("%d/%b/%Y:%H:%M:%S +0000")
        size = random.choice([1024, 2048, 65_536_000])  # one huge transfer
        apache_lines.append(
            f'203.0.113.77 - - [{ts}] "GET /data/export.zip HTTP/1.1" 200 {size}'
        )

    apache_path = output_dir / "access.log"
    apache_path.write_text("\n".join(apache_lines))

    logger.info("Demo logs written to %s", output_dir)
    return {"syslog": syslog_path, "apache": apache_path}


def main():
    parser = argparse.ArgumentParser(
        description="SIEM Log Analyzer — multi-format security event correlation engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo
  python main.py --log sample_logs/auth.log --format syslog --report reports/
  python main.py --log sample_logs/access.log --format apache --report reports/
        """,
    )
    parser.add_argument("--log", type=Path, help="Path to log file")
    parser.add_argument(
        "--format",
        choices=["syslog", "apache", "cloudtrail"],
        default="syslog",
        help="Log format (default: syslog)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("reports"),
        help="Output directory for reports (default: reports/)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate synthetic logs and run full pipeline demo",
    )
    args = parser.parse_args()

    pipeline = SIEMPipeline()

    if args.demo:
        print("\n🔐 SIEM Log Analyzer — Demo Mode\n" + "=" * 40)
        logs = generate_demo_logs(Path("sample_logs"))
        pipeline.ingest_file(logs["syslog"], fmt="syslog")
        pipeline.ingest_file(logs["apache"], fmt="apache")
    elif args.log:
        pipeline.ingest_file(args.log, fmt=args.format)
    else:
        parser.print_help()
        return

    paths = pipeline.run_report(args.report)
    total_alerts = len(pipeline.engine.alerts)

    print(f"\n{'='*40}")
    print(f"✅ Analysis Complete")
    print(f"   Alerts generated : {total_alerts}")
    print(f"   Critical         : {sum(1 for a in pipeline.engine.alerts if a.severity == 'CRITICAL')}")
    print(f"   High             : {sum(1 for a in pipeline.engine.alerts if a.severity == 'HIGH')}")
    print(f"   JSON report      : {paths['json']}")
    print(f"   Markdown report  : {paths['markdown']}")
    print(f"{'='*40}\n")


if __name__ == "__main__":
    main()

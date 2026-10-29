"""CLI entry point for Framework Detector."""

import argparse

from framework_detector.detector import FrameworkDetector


def main():
    parser = argparse.ArgumentParser(
        prog="fwd",
        description="Detect web frameworks from HTTP responses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  fwd https://example.com
  fwd https://example.com --no-probe
  fwd https://example.com -v --timeout 15
  python -m framework_detector https://example.com
""",
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip path probing (faster, stealthier)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--threads", type=int, default=10, help="Threads for path probing (default: 10)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    args = parser.parse_args()

    detector = FrameworkDetector(
        url=args.url,
        timeout=args.timeout,
        probe_paths=not args.no_probe,
        threads=args.threads,
        verbose=args.verbose,
    )
    detector.run()


if __name__ == "__main__":
    main()

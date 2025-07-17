import argparse
import json
import logging
import sys
from datetime import datetime

from directory import DirectoryFuzzer
from api import APIScanner
from fuzzing import NewtonScanner
from parameter import ParameterFuzzer
from vhost import VHostEnumerator
from wayback import WaybackEnumerator

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

def parse_args():
    parser = argparse.ArgumentParser(description="Comprehensive Web Application Security Fuzzer")
    parser.add_argument("--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--phases", nargs="*", default=["all"],
                        help="Scan phases to run: recon, dir, vhost, api, param, vuln, report, all")
    parser.add_argument("--output", default="fuzz_report.json", help="Output report file (JSON)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--threads", type=int, default=10, help="Thread count for modules that support it")
    parser.add_argument("--wordlist", help="Wordlist for directory/parameter fuzzing")
    parser.add_argument("--vhosts-wordlist", help="Wordlist for vhost enumeration")
    parser.add_argument("--api-key", help="API key for API scanning (if needed)")
    parser.add_argument("--scan-mode", choices=["quick", "full", "stealth"], default="full", help="API scan mode")
    parser.add_argument("--param-mode", choices=["param-name", "param-value", "path", "body", "json"], help="Parameter fuzzing mode")
    parser.add_argument("--output-file", help="Output file for module results (optional)")
    parser.add_argument("--fast-scan", action="store_true", help="Enable fast scan mode (limits wordlist size for testing)")
    parser.add_argument("--param-wordlist", help="Wordlist for parameter fuzzing")
    parser.add_argument('--wayback', action='store_true', help='Enable Wayback Machine enumeration')
    # Add more global options as needed
    return parser.parse_args()

def main():
    args = parse_args()
    setup_logging(args.verbose)

    # Allow for a fast scan mode (limit wordlist size)
    fast_scan = getattr(args, 'fast_scan', False)
    wordlist = args.wordlist
    vhosts_wordlist = args.vhosts_wordlist
    param_wordlist = getattr(args, 'param_wordlist', None)
    if fast_scan and wordlist:
        # Truncate wordlist for fast scan
        with open(wordlist, 'r') as f:
            lines = [next(f) for _ in range(50)]
        with open('fast_wordlist.txt', 'w') as f:
            f.writelines(lines)
        wordlist = 'fast_wordlist.txt'
    if fast_scan and vhosts_wordlist:
        with open(vhosts_wordlist, 'r') as f:
            lines = [next(f) for _ in range(50)]
        with open('fast_vhosts_wordlist.txt', 'w') as f:
            f.writelines(lines)
        vhosts_wordlist = 'fast_vhosts_wordlist.txt'
    if fast_scan and param_wordlist:
        with open(param_wordlist, 'r') as f:
            lines = [next(f) for _ in range(50)]
        with open('fast_param_wordlist.txt', 'w') as f:
            f.writelines(lines)
        param_wordlist = 'fast_param_wordlist.txt'

    # Config for each module
    dir_config = {
        'url': args.url,
        'threads': min(args.threads, 10),  # Limit threads for speed
        'wordlist': wordlist,
        'output_file': args.output,
        'silent': not args.verbose,
        'verbose': args.verbose,
        'log_file': 'fuzzer.log',
    }
    param_config = {
        'url': args.url,
        'threads': min(args.threads, 10),
        'wordlist': param_wordlist or wordlist,
        'output_file': args.output,
        'silent': not args.verbose,
        'verbose': args.verbose,
        'log_file': 'fuzzer.log',
    }
    vhost_config = {
        'target': args.url,
        'threads': min(args.threads, 10),
        'vhosts_wordlist': vhosts_wordlist,
        'output_file': args.output,
        'silent': not args.verbose,
        'verbose': args.verbose,
        'log_file': 'fuzzer.log',
    }
    api_config = {
        'url': args.url,
        'threads': args.threads,
        'output_file': args.output,
        'silent': not args.verbose,
        'verbose': args.verbose,
        'log_file': 'fuzzer.log',
    }
    recon_config = {
        'url': args.url,
        'threads': args.threads,
        'output_file': args.output,
        'silent': not args.verbose,
        'verbose': args.verbose,
        'log_file': 'fuzzer.log',
    }

    results = {}
    errors = {}

    if 'recon' in args.phases:
        newton = NewtonScanner(args.url, config=recon_config)
        recon_result = newton.run(recon_config)
        results['recon'] = recon_result.get('findings', [])
        errors['recon'] = recon_result.get('errors', [])
    if 'dir' in args.phases:
        dir_fuzzer = DirectoryFuzzer(dir_config)
        dir_result = dir_fuzzer.run()
        results['dir'] = dir_result.get('findings', [])
        errors['dir'] = dir_result.get('errors', [])
    if 'vhost' in args.phases:
        vhost_enum = VHostEnumerator(vhost_config)
        vhost_result = vhost_enum.run()
        results['vhost'] = vhost_result.get('findings', [])
        errors['vhost'] = vhost_result.get('errors', [])
    if 'api' in args.phases:
        api_scan = APIScanner(args.url, options=api_config)
        api_result = api_scan.run()
        results['api'] = api_result.get('findings', {})
        errors['api'] = api_result.get('errors', [])
    if 'param' in args.phases:
        param_fuzzer = ParameterFuzzer(param_config)
        param_result = param_fuzzer.run()
        results['param'] = param_result.get('findings', [])
        errors['param'] = param_result.get('errors', [])
    if getattr(args, 'wayback', False):
        wayback_enum = WaybackEnumerator(dir_config) # Use dir_config for consistency with other modules
        wayback_result = wayback_enum.run()
        results['wayback'] = wayback_result['findings']
        if wayback_result['errors']:
            errors['wayback'] = wayback_result['errors']

    # Unified report
    report = {
        'results': results,
        'errors': errors,
        'timestamp': datetime.utcnow().isoformat(),
    }
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main() 
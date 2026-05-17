import multiprocessing
import argparse
import time
import sys
import redis

from ct_stream import run_ct_stream
from worker import run_worker, PROCESSED_SET

def main():
    parser = argparse.ArgumentParser(description="Threat Infrastructure Graphing Stack")
    parser.add_argument(
        "--rescan",
        action="store_true",
        help="Re-scan all previously processed targets to detect infrastructure changes"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        help="Number of parallel worker processes (default: 3)"
    )
    args = parser.parse_args()

    WORKER_COUNT = args.workers
    processes = []

    if args.rescan:
        # Rescan mode: re-queue all previously processed IPs
        r = redis.Redis(host="localhost", port=6379)
        processed = r.smembers(PROCESSED_SET)

        if not processed:
            print("[!] No previously processed targets found. Run a normal scan first.")
            sys.exit(1)

        print(f"[*] RESCAN MODE — Re-queuing {len(processed)} previously scanned targets...")
        for ip in processed:
            r.lpush("targets", ip)

        # Start workers in rescan mode (no CT stream needed)
        for i in range(WORKER_COUNT):
            w_proc = multiprocessing.Process(
                target=run_worker,
                args=(True,),
                name=f"Worker_{i+1}"
            )
            w_proc.start()
            processes.append(w_proc)

        # Wait for all workers to finish (they exit when queue is drained)
        for p in processes:
            p.join()

        print("[✓] Rescan complete.")

    else:
        # Normal discovery mode
        print(f"[*] Starting Threat Reconnaissance Stack ({WORKER_COUNT} workers)...")

        # Start the CT Stream ingestion process
        ct_proc = multiprocessing.Process(target=run_ct_stream, name="CT_Stream")
        ct_proc.start()
        processes.append(ct_proc)

        # Start the Recon Workers
        for i in range(WORKER_COUNT):
            w_proc = multiprocessing.Process(
                target=run_worker,
                args=(False,),
                name=f"Worker_{i+1}"
            )
            w_proc.start()
            processes.append(w_proc)

        try:
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n[*] Shutting down all processes...")
            for p in processes:
                p.terminate()
                p.join()
            sys.exit(0)

if __name__ == "__main__":
    main()

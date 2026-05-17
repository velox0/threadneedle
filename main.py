import multiprocessing
import time
import sys

from ct_stream import run_ct_stream
from worker import run_worker

def main():
    print("[*] Starting Threat Reconnaissance Stack...")
    
    # We can spawn multiple workers to handle the heavy load of scanning
    # Change WORKER_COUNT if you want more parallel scanning power!
    WORKER_COUNT = 3
    
    processes = []
    
    # Start the CT Stream ingestion process
    ct_proc = multiprocessing.Process(target=run_ct_stream, name="CT_Stream")
    ct_proc.start()
    processes.append(ct_proc)
    
    # Start the Recon Workers
    for i in range(WORKER_COUNT):
        w_proc = multiprocessing.Process(target=run_worker, name=f"Worker_{i+1}")
        w_proc.start()
        processes.append(w_proc)

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\\n[*] Shutting down all processes...")
        for p in processes:
            p.terminate()
            p.join()
        sys.exit(0)

if __name__ == "__main__":
    main()

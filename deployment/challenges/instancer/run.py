from multiprocessing import Process

import uvicorn
from instancer.core.prunner import pruner_process


if __name__ == "__main__":
    Process(target=pruner_process, daemon=True).start()
    # The admission lock is process-local. Do not increase workers.
    uvicorn.run("guard:app", host="0.0.0.0", port=1337, workers=1,
                server_header=False, proxy_headers=False, access_log=False)

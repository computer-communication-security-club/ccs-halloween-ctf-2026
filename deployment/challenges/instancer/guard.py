"""Small admission layer around the pinned upstream instancer.

Only pre-approved configs can run; a single API worker serializes starts and
checks all existing containers (including failed ones) before admitting more.
Upstream continues to own per-team locking, expiry, routing, and cleanup.
"""

import asyncio
import json
import os
from pathlib import Path

from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from instancer.core import instances
from instancer.core.cache import redis
from instancer.core.config import config
from instancer.core.instancer.const import ContainerLabels
from instancer.protocol.types import InstancerConfig, InstancerExpose
from instancer.setup import app
import raw_https  # Registers transparent TLS stream routing before any starts.

POLICY = json.loads(Path(os.environ.get("CCS_POLICY", "/etc/ccs/policy.json")).read_text())
START_LOCK = asyncio.Lock()
UPSTREAM_START = instances.start_instance
UPSTREAM_RENEW = instances.renew_instance


def approved(form, *, creating):
    entry = POLICY["challenges"].get(form.challenge_integration_id)
    if entry is None or not 1000 <= form.timeout_milliseconds <= POLICY["ttl_seconds"] * 1000:
        raise HTTPException(422, "Challenge or lifetime is not allowed on this worker")
    if creating:
        allowed_config = InstancerConfig.model_validate(entry["config"])
        allowed_expose = [InstancerExpose.model_validate(item) for item in entry["expose"]]
        if form.config != allowed_config or form.expose != allowed_expose:
            raise HTTPException(422, "Instance configuration does not match the deployed policy")


async def start(form):
    approved(form, creating=True)
    if START_LOCK.locked():
        raise HTTPException(429, "Another instance is starting; retry shortly")
    async with START_LOCK:
        docker = instances.get_docker()
        containers = await docker.containers.list(all=True, filters={
            "label": [f"{ContainerLabels.MANAGED_BY}={config.DOCKER_MANAGER_NAME}"]})
        details = await asyncio.gather(*(container.show() for container in containers))
        active = {
            (item["Config"]["Labels"][ContainerLabels.CHALLENGE],
             item["Config"]["Labels"][ContainerLabels.TEAM_ID])
            for item in details
        }
        challenge_count = sum(challenge == form.challenge_integration_id for challenge, _ in active)
        if len(active) >= POLICY["max_instances"] or challenge_count >= POLICY["max_per_challenge"]:
            raise HTTPException(429, "Worker capacity reached; stop an instance or wait for expiry")
        key = f"ccs:start:{form.team_id}"
        if not await redis.set(key, "1", ex=10, nx=True):
            raise HTTPException(429, "Wait ten seconds between instance starts")
        return await UPSTREAM_START(form)


async def renew(form):
    approved(form, creating=False)
    return await UPSTREAM_RENEW(form)


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Never echo request bodies containing the shared API token or flags.
    return JSONResponse(status_code=422, content={"message": "Invalid instance request"})


@app.get("/healthz")
async def health():
    await redis.ping()
    await instances.get_docker().version()
    return {"status": "ok"}


instances.start_instance = start
instances.renew_instance = renew

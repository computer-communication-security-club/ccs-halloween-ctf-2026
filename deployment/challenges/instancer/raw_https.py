"""Terminate TLS without parsing HTTP for challenges that take over the socket."""
from instancer.core.config import config
from instancer.core.instancer import containers, traefik
from instancer.protocol.types import ExposeKind

_upstream = traefik.expose_ports


def expose_ports(labels, svc_name, exposes, instance_id, routing_network, global_indices):
    result = _upstream(labels, svc_name, exposes, instance_id, routing_network, global_indices)
    if not routing_network:
        return result
    for index, expose in enumerate(exposes.get(svc_name, [])):
        if expose.kind != ExposeKind.HTTPS:
            continue
        name = f"{config.PREFIX}-{instance_id}-{svc_name}-{index}"
        for key in list(labels):
            if key.startswith(f"traefik.http.routers.{name}.") or key.startswith(f"traefik.http.services.{name}."):
                del labels[key]
        labels.update({
            f"traefik.tcp.routers.{name}.rule": f"HostSNI(`{traefik.expose_host(expose, instance_id)}`)",
            f"traefik.tcp.routers.{name}.entrypoints": config.TRAEFIK_HTTPS_ENTRYPOINT,
            f"traefik.tcp.routers.{name}.tls": "true",
            f"traefik.tcp.routers.{name}.service": name,
            f"traefik.tcp.services.{name}.loadbalancer.server.port": str(expose.container_port),
            f"traefik.http.routers.{name}-redirect.service": "noop@internal",
        })
    return result


containers.expose_ports = expose_ports

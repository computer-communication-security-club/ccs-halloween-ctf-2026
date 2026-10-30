# Private runtime only: dist intentionally contains no player downloads.
FROM itzg/minecraft-server:java25@sha256:f7f2222512810f0f0e85133913622cf639be77a5dd1d4b11f24ab675da6ba742 AS build
USER 0:0
WORKDIR /build
ADD --checksum=sha256:d052f14d7a173734fba553711e5b570162e2f2a313267ee31a21b975a679be64 https://piston-data.mojang.com/v1/objects/33680f5f2ac32864d6d7cf5e56a705fdb3e05f4c/server.jar /build/server.jar
COPY src/world /build/world
COPY src/prepare-world.sh /build/prepare-world.sh
COPY flag.txt /build/flag.txt
RUN bash /build/prepare-world.sh /build/world /build/flag.txt

FROM itzg/minecraft-server:java25@sha256:f7f2222512810f0f0e85133913622cf639be77a5dd1d4b11f24ab675da6ba742 AS runtime
USER 0:0
COPY --from=build /build/server.jar /opt/sict/server.jar
COPY --from=build /build/world /opt/sict/world
COPY --chmod=755 src/start.sh /opt/sict/start.sh
COPY --chmod=755 src/admin.sh /opt/sict/admin
RUN mkdir -p /data && chown 1000:1000 /data
WORKDIR /data
USER 1000:1000
EXPOSE 25565
ENTRYPOINT ["/opt/sict/start.sh"]

FROM scratch AS dist

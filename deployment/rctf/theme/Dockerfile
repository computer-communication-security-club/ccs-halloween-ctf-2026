FROM ghcr.io/otter-sec/rctf@sha256:5fd7cd4379e9bc87f181200fa061600a5fba27d035928407e13f29fda839d3c2
COPY assets/ /app/static/halloween/
COPY assets/theme.js /app/static/theme.js
# Load after application styles. Delete compressed originals so nginx cannot
# serve an old index or pre-paint script to clients accepting gzip/brotli.
RUN test -f /app/static/index.html \
    && sed -i 's|src="/theme.js"|src="/halloween/theme.js"|;s|</head>|<link rel="stylesheet" href="/halloween/halloween.css"><script defer src="/halloween/pumpkin.js"></script></head>|' /app/static/index.html \
    && rm -f /app/static/index.html.gz /app/static/index.html.br /app/static/theme.js.gz /app/static/theme.js.br

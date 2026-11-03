# The sample service of the swarm lab. Answers with the node serving the request, which shows the
# routing mesh at work: any node accepts a request, and any node with a replica may answer it.
FROM nginx:alpine

LABEL segmentra.demo-lab="1"

RUN printf '#!/bin/sh\necho "Hello from $(hostname)" > /usr/share/nginx/html/index.html\n' > /docker-entrypoint.d/05-hello.sh \
 && chmod +x /docker-entrypoint.d/05-hello.sh

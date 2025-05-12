#!/usr/bin/env bash
# Purpose: expose both the KIND API (6445) *and* Argo CD NodePort (30080)
# to the dev-container via a tiny NGINX stream proxy.

: "${SCRIPT_PATH:=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
set -Eeuo pipefail

log() { printf "[%s] %s\n" "$(date +'%H:%M:%S')" "$*"; }

launch_kind_api_proxy() {
  log "Launching NGINX stream-proxy on host.docker.internal:6445 (API) + 30080 (Argo CD)"

  # locate the control-plane container for this cluster
  local CP
  CP=$(docker ps --filter "label=io.x-k8s.kind.cluster=${KIND_CLUSTER_NAME}" \
                 --filter "label=io.x-k8s.kind.role=control-plane" \
                 --format '{{.Names}}')
  [[ -n "${CP}" ]] || { log "Could not find control-plane container"; return 1; }

  # scratch workspace
  : "${WORK_DIR:=$(mktemp -d)}"

  # ── nginx.conf ──────────────────────────────────────────────────────────────
  cat >"${WORK_DIR}/nginx-kind.conf" <<EOF
events {}
stream {
  upstream apiserver  { server ${CP}:6443; }
  upstream argocd_http  { server ${CP}:30080; }
  upstream argocd_https { server ${CP}:30443; }

  server {            # Kubernetes API
    listen 6443;
    proxy_pass apiserver;
  }
  server {            # Argo CD NodePort (HTTP)
    listen 30080;
    proxy_pass argocd_http;
  }
  server {            # Argo CD NodePort (HTTPS)
    listen 30443;
    proxy_pass argocd_https;
  }
}
EOF
  # ── Dockerfile ──────────────────────────────────────────────────────────────
  cat >"${WORK_DIR}/Dockerfile" <<'EOF'
FROM nginx:1.25-alpine
COPY nginx-kind.conf /etc/nginx/nginx.conf
CMD ["nginx","-g","daemon off;","-c","/etc/nginx/nginx.conf"]
EOF
  # build & (re)run
  docker build -q -f "${WORK_DIR}/Dockerfile" -t kind-api-proxy-img "${WORK_DIR}"
  docker rm -f kind-api-proxy >/dev/null 2>&1 || true
  docker run -d --name kind-api-proxy --network kind \
         -p 6445:6443 -p 30080:30080 -p 30443:30443 -p 3000:3000 kind-api-proxy-img

  # wait until the API side is healthy
  until curl -ks https://host.docker.internal:6445/livez >/dev/null 2>&1; do sleep 2; done
}

patch_kubeconfigs() {
  log "Patching kubeconfigs to use host.docker.internal:6445"

  local KCONF="$HOME/.kube/config"
  kind get kubeconfig --name "${KIND_CLUSTER_NAME}" > "$KCONF"
  sed -i -E 's#(^[[:space:]]*server:).*#\1 https://host.docker.internal:6445#' "$KCONF"
  export KUBECONFIG="$KCONF"
  kubectl config use-context "kind-${KIND_CLUSTER_NAME}"

  # copy for Headlamp
  local WIN_KCONF="${SCRIPT_PATH}/kind-headlamp.yaml"
  kind export kubeconfig --name "${KIND_CLUSTER_NAME}" --kubeconfig "$WIN_KCONF"
  sed -i -E 's#(^[[:space:]]*server:).*#\1 https://localhost:6445#' "$WIN_KCONF"
  chmod 0644 "$WIN_KCONF"
  log "📄  Headlamp kubeconfig written to $WIN_KCONF"
}

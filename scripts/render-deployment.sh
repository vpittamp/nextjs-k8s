#!/usr/bin/env bash
# Render every *.yaml.tpl under $DEPLOY_DIR → apps/infra-secrets/base
set -Eeuo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-$(git rev-parse --show-toplevel)/deployments}"
OUT_DIR="apps/infra-secrets/base"
APP_FILE="apps/infra-secrets/application.yaml"

mkdir -p "$OUT_DIR"

# These vars are already exported by wi-kind-setup.sh
export APP_ID TENANT_ID ESO_NS REGISTRY_NAME REGISTRY_NS VAULT_URL VAULT_ID SA_NAME

for tpl in "$DEPLOY_DIR"/*.yaml.tpl; do
  envsubst < "$tpl" > "$OUT_DIR/$(basename "${tpl%.tpl}")"
done

# derive "<owner>/<repo>"
GITHUB_REPOSITORY=$(git config --get remote.origin.url | \
                    sed -E 's#.+[:/](.+/[^/]+)\.git#\1#')

cat >"$APP_FILE" <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: infra-secrets
  namespace: argocd
  finalizers: [resources-finalizer.argocd.argoproj.io]
spec:
  project: default
  source:
    repoURL: https://github.com/${GITHUB_REPOSITORY}.git
    targetRevision: HEAD
    path: apps/infra-secrets/base
  destination:
    name: in-cluster
    namespace: external-secrets
  syncPolicy:
    automated: { prune: true, selfHeal: true }
    syncOptions: ["CreateNamespace=true"]
EOF

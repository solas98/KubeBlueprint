/* ═══════════════════════════════════════════
   K8s Blueprint Generator — Frontend JS
   ═══════════════════════════════════════════ */

let currentMode = 'helm';
let generatedFiles = [];
let currentFileIndex = -1;
let cmdDrawerOpen = true;

// ── Mode Selection ─────────────────────────────────────
function setMode(mode) {
  currentMode = mode;
  document.querySelectorAll('.mode-card').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + mode).classList.add('active');
}

// ── KEDA toggle ────────────────────────────────────────
function toggleKeda(enabled) {
  document.getElementById('keda-opts').classList.toggle('hidden', !enabled);
  if (enabled) updateKedaTrigger(document.getElementById('keda-trigger').value);
}

function updateKedaTrigger(val) {
  document.querySelectorAll('.trigger-fields').forEach(el => el.classList.add('hidden'));
  const el = document.getElementById('keda-' + val);
  if (el) el.classList.remove('hidden');
}

// ── Secret provider toggle ─────────────────────────────
function updateSecretProvider(val) {
  document.querySelectorAll('.secret-opts').forEach(el => el.classList.add('hidden'));
  if (val === 'external-secrets') {
    document.getElementById('eso-opts').classList.remove('hidden');
    updateESOBackend(document.getElementById('es-backend-provider').value);
  }
  if (val === 'vault') document.getElementById('vault-opts').classList.remove('hidden');
}

// ── ESO backend provider toggle ────────────────────────
function updateESOBackend(val) {
  document.querySelectorAll('.eso-backend-fields').forEach(el => el.classList.add('hidden'));
  const el = document.getElementById('eso-' + val);
  if (el) el.classList.remove('hidden');

  // Update store name placeholder based on provider
  const storeNameEl = document.getElementById('es-store-name');
  if (storeNameEl) {
    const defaults = { aws: 'aws-secretsmanager', gcp: 'gcp-secretmanager', azure: 'azure-keyvault', vault: 'vault-backend' };
    storeNameEl.placeholder = defaults[val] || 'my-secret-store';
    if (!storeNameEl.value) storeNameEl.value = '';
  }
}
// ── Istio toggle ───────────────────────────────────
function toggleIstio(enabled) {
  document.getElementById('istio-opts').classList.toggle('hidden', !enabled);
}

function updateIstiAuthzPolicy() {
  const ap = document.getElementById('istio-ap').checked;
  document.getElementById('istio-authz-policy').classList.toggle('hidden', !ap);
}
// ── Collect form data ──────────────────────────────────
function collectRequest() {
  const resources = Array.from(document.querySelectorAll('.chips input:checked'))
    .map(i => i.value);

  const envs = Array.from(document.querySelectorAll('.env-pill input:checked'))
    .map(i => i.value);

  const kedaEnabled = document.getElementById('keda-enabled').checked;
  const kedaTrigger = document.getElementById('keda-trigger').value;

  const secretProvider = document.getElementById('secret-provider').value;

  return {
    mode: currentMode,
    appName: document.getElementById('app-name').value.trim() || 'my-app',
    image: document.getElementById('image').value.trim() || 'nginx:1.25-alpine',
    port: (document.getElementById('port').value || '8080').toString(),
    resources,
    envs,
    security: {
      nonRoot:   document.getElementById('sec-nonroot').checked,
      readOnly:  document.getElementById('sec-readonly').checked,
      dropCaps:  document.getElementById('sec-caps').checked,
      seccomp:   document.getElementById('sec-seccomp').checked,
      noPrivEsc: document.getElementById('sec-privesc').checked,
      netPolicy: document.getElementById('sec-netpol').checked,
    },
    keda: {
      enabled: kedaEnabled,
      trigger: kedaTrigger,
      kafkaBootstrapServers: v('kafka-bs'),
      kafkaTopic: v('kafka-topic'),
      kafkaConsumerGroup: v('kafka-cg'),
      kafkaLagThreshold: v('kafka-lag'),
      rabbitMQHost: v('rmq-host'),
      rabbitMQQueue: v('rmq-queue'),
      redisAddress: v('redis-addr'),
      redisListName: v('redis-list'),
      sqsQueueURL: v('sqs-url'),
      sqsRegion: v('sqs-region'),
      prometheusServerAddress: v('prom-url'),
      prometheusQuery: v('prom-query'),
      cronTimezone: v('cron-tz'),
      cronStart: v('cron-start'),
      cronEnd: v('cron-end'),
      cronDesired: v('cron-desired'),
    },
    secrets: {
      provider: secretProvider,
      esBackendProvider: document.getElementById('es-backend-provider')?.value || 'aws',
      esAwsService: document.getElementById('eso-aws-service')?.value || 'SecretsManager',
      esSecretStoreName: v('es-store-name'),
      esSecretStoreKind: document.getElementById('es-store-kind')?.value || 'SecretStore',
      esRemotePath: v('es-remote-path'),
      esAwsRegion: v('eso-aws-region'),
      esAwsRoleArn: v('eso-aws-role-arn'),
      esGcpProjectId: v('eso-gcp-project'),
      esAzureVaultUrl: v('eso-azure-vault-url'),
      esVaultServer: v('eso-vault-server'),
      esVaultPath: v('eso-vault-path'),
      esVaultRole: v('eso-vault-role'),
      vaultAddress: v('vault-addr'),
      vaultRole: v('vault-role'),
      vaultPath: v('vault-path'),
      vaultMountPath: v('vault-mount'),
    },
    istio: {
      enabled: document.getElementById('istio-enabled').checked,
      gatewayName: v('istio-gw-name') || 'main-gateway',
      meshGateway: document.getElementById('istio-mesh-gw').checked,
      virtualServicePort: (document.getElementById('istio-vs-port').value || '80').toString(),
      destinationRule: document.getElementById('istio-dr').checked,
      envoyFilter: document.getElementById('istio-ef').checked,
      authorizationPolicy: document.getElementById('istio-ap').checked,
      authzPolicyAction: document.getElementById('istio-authz-action')?.value || 'ALLOW',
    }
  };
}

function v(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : '';
}

// ── Generate ───────────────────────────────────────────
async function generate() {
  const btn = document.getElementById('generate-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Generating...';

  try {
    const req = collectRequest();
    const resp = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req)
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text);
    }

    const data = await resp.json();
    generatedFiles = data.files || [];

    showOutput(req);
    showToast(`✓ Generated ${generatedFiles.length} files`);

  } catch (err) {
    showToast('✗ ' + err.message, true);
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Generate Blueprint';
  }
}

// ── Show output ────────────────────────────────────────
function showOutput(req) {
  document.getElementById('placeholder').classList.add('hidden');
  const area = document.getElementById('output-area');
  area.classList.remove('hidden');

  document.getElementById('output-title').textContent =
    `${req.appName} · ${req.mode.toUpperCase()} · ${generatedFiles.length} files`;
  document.getElementById('file-count').textContent = generatedFiles.length + ' files';

  renderFileTree();
  buildCommands(req);

  // Auto-select first file
  if (generatedFiles.length > 0) selectFile(0);
}

// ── File Tree ──────────────────────────────────────────
function renderFileTree() {
  const tree = document.getElementById('file-tree');
  tree.innerHTML = '';

  // Group by directory
  const dirs = {};
  const roots = [];
  generatedFiles.forEach((f, i) => {
    const parts = f.path.split('/');
    if (parts.length === 1) {
      roots.push({ name: f.path, idx: i });
    } else {
      const dir = parts.slice(0, -1).join('/');
      if (!dirs[dir]) dirs[dir] = [];
      dirs[dir].push({ name: parts[parts.length - 1], idx: i, fullPath: f.path });
    }
  });

  // Root files
  roots.forEach(item => {
    tree.appendChild(makeFileEl(item.name, item.idx, 0));
  });

  // Directories
  const seenDirs = new Set();
  Object.keys(dirs).sort().forEach(dir => {
    const parts = dir.split('/');

    // Add parent dirs
    let accum = '';
    parts.forEach((part, depth) => {
      accum = accum ? accum + '/' + part : part;
      if (!seenDirs.has(accum)) {
        seenDirs.add(accum);
        const el = document.createElement('div');
        el.className = 'tree-dir';
        el.innerHTML = `<span class="ti" style="margin-left:${depth * 14}px">📁</span><span>${part}/</span>`;
        tree.appendChild(el);
      }
    });

    dirs[dir].forEach(item => {
      tree.appendChild(makeFileEl(item.name, item.idx, parts.length));
    });
  });
}

function makeFileEl(name, idx, depth) {
  const ext = name.split('.').pop();
  const cls = ext === 'yaml' || ext === 'yml' ? 'yaml'
    : ext === 'tpl' ? 'tpl'
    : ext === 'md' ? 'md'
    : ext === 'txt' ? 'txt'
    : 'ignore';

  const el = document.createElement('div');
  el.className = `tree-file ${cls}`;
  el.dataset.idx = idx;
  el.innerHTML = `<span class="ti" style="margin-left:${depth * 14}px"></span><span>${name}</span>`;
  el.onclick = () => selectFile(idx);
  return el;
}

function selectFile(idx) {
  currentFileIndex = idx;
  document.querySelectorAll('.tree-file').forEach(el => {
    el.classList.toggle('active', parseInt(el.dataset.idx) === idx);
  });

  const file = generatedFiles[idx];
  document.getElementById('code-filepath').textContent = file.path;
  document.getElementById('code-viewer').innerHTML = highlight(file.content);
}

// ── Syntax Highlighting ────────────────────────────────
function highlight(code) {
  // Escape HTML
  let h = code
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Comments
  h = h.replace(/(#[^\n]*)/g, '<span class="cc">$1</span>');
  // Helm templates {{ }}
  h = h.replace(/(\{\{[^}]+\}\})/g, '<span class="cs">$1</span>');
  // apiVersion / kind / metadata etc.
  h = h.replace(/^(\s*)(apiVersion|kind|metadata|spec|template|containers?|securityContext|resources|env|ports?|volumes?|volumeMounts?|affinity|topologySpreadConstraints|imagePullPolicy|serviceAccountName|automountServiceAccountToken|livenessProbe|readinessProbe|startupProbe|lifecycle|strategy|selector|replicas|labels|annotations|namespace|name|image)(:)/gm,
    '$1<span class="cd">$2</span>$3');
  // Keys (lines with colon)
  h = h.replace(/^(\s*)([a-zA-Z_][a-zA-Z0-9_\-]*)(:)/gm, '$1<span class="ck">$2</span>$3');
  // Booleans
  h = h.replace(/:\s*(true|false)\b/g, ': <span class="cb">$1</span>');
  // Numbers
  h = h.replace(/:\s*(\d+m?i?)\b/g, ': <span class="cn">$1</span>');
  // Quoted strings
  h = h.replace(/:\s*(&quot;[^&]*&quot;|"[^"]*")/g, ': <span class="cv">$1</span>');

  return h;
}

// ── Copy file ──────────────────────────────────────────
function copyCurrentFile() {
  if (currentFileIndex < 0) return;
  const content = generatedFiles[currentFileIndex].content;
  copyToClipboard(content, document.getElementById('btn-copy'));
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
    }
    showToast('✓ Copied to clipboard');
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('✓ Copied');
  });
}

// ── Commands ───────────────────────────────────────────
function buildCommands(req) {
  const body = document.getElementById('cmd-drawer-body');
  body.innerHTML = '';

  const name = req.appName;
  const mode = req.mode;
  const envs = req.envs || ['dev', 'test', 'staging', 'prod'];

  const cards = [];

  if (mode === 'helm') {
    cards.push({ env: 'info', title: 'Lint Chart', cmd:
      `helm lint ./${name} -f ${name}/values.yaml --strict` });
      if (envs.includes('dev')) {
        cards.push({ env: 'info', title: 'Template Render (dev)', cmd:
          `helm template ${name} ./${name} \\\n  -f ${name}/values.yaml \\\n  -f ${name}/values-dev.yaml \\\n  --namespace ${name}-dev` });
        cards.push({ env: 'info', title: 'Dry Run (dev)', cmd:
          `helm upgrade --install ${name} ./${name} \\\n  --namespace ${name}-dev --create-namespace \\\n  -f ${name}/values.yaml -f ${name}/values-dev.yaml \\\n  --dry-run --debug` });
      }

    if (envs.includes('dev')) cards.push({ env: 'dev', title: 'Deploy → Dev', cmd:
      `helm upgrade --install ${name} ./${name} \\\n  --namespace ${name}-dev --create-namespace \\\n  -f ${name}/values.yaml -f ${name}/values-dev.yaml` });

    if (envs.includes('staging')) cards.push({ env: 'staging', title: 'Deploy → Staging', cmd:
      `helm upgrade --install ${name} ./${name} \\\n  --namespace ${name}-staging --create-namespace \\\n  -f ${name}/values.yaml -f ${name}/values-staging.yaml \\\n  --wait --timeout 5m` });

    if (envs.includes('prod')) {
      cards.push({ env: 'prod', title: 'Deploy → Production', cmd:
        `helm upgrade --install ${name} ./${name} \\\n  --namespace ${name}-prod --create-namespace \\\n  -f ${name}/values.yaml -f ${name}/values-prod.yaml \\\n  --atomic --cleanup-on-fail \\\n  --wait --timeout 5m` });
      cards.push({ env: 'prod', title: 'Rollback Production', cmd:
        `helm rollback ${name} 0 -n ${name}-prod --wait` });
    }

    cards.push({ env: 'info', title: 'Pod Status', cmd:
      `kubectl get pods -n ${name}-prod \\\n  -l app.kubernetes.io/name=${name} -w` });
    cards.push({ env: 'info', title: 'Tail Logs', cmd:
      `kubectl logs -n ${name}-prod \\\n  -l app.kubernetes.io/name=${name} \\\n  --tail=100 -f` });
    cards.push({ env: 'info', title: 'Describe Deployment', cmd:
      `kubectl describe deployment/${name} -n ${name}-prod` });
    cards.push({ env: 'info', title: 'Get Events', cmd:
      `kubectl get events -n ${name}-prod \\\n  --sort-by=.metadata.creationTimestamp` });

  } else {
    // kustomize
    cards.push({ env: 'info', title: 'Build Base (preview)', cmd:
      `kubectl kustomize base/` });
    cards.push({ env: 'info', title: 'Dry Run (dev)', cmd:
      `kubectl kustomize overlays/dev | \\\n  kubectl apply --dry-run=client -f -` });
    cards.push({ env: 'info', title: 'Validate (kubeval)', cmd:
      `kubectl kustomize overlays/prod | kubeval --strict` });

    if (envs.includes('dev')) cards.push({ env: 'dev', title: 'Apply → Dev', cmd:
      `kubectl apply -k overlays/dev\nkubectl rollout status deployment/${name} \\\n  -n ${name}-dev` });

    if (envs.includes('staging')) cards.push({ env: 'staging', title: 'Apply → Staging', cmd:
      `kubectl apply -k overlays/staging\nkubectl rollout status deployment/${name} \\\n  -n ${name}-staging --timeout=5m` });

    if (envs.includes('prod')) {
      cards.push({ env: 'prod', title: 'Apply → Production', cmd:
        `kubectl apply -k overlays/prod\nkubectl rollout status deployment/${name} \\\n  -n ${name}-prod --timeout=5m` });
      cards.push({ env: 'prod', title: 'Rollback Production', cmd:
        `kubectl rollout undo deployment/${name} -n ${name}-prod` });
    }

    cards.push({ env: 'info', title: 'FluxCD — GitOps', cmd:
      `flux create source git ${name} \\\n  --url=https://github.com/org/${name} \\\n  --branch=main\n\nflux create kustomization ${name}-prod \\\n  --source=${name} \\\n  --path="./overlays/prod" \\\n  --prune=true --interval=5m \\\n  --health-check-timeout=3m` });
    cards.push({ env: 'info', title: 'ArgoCD — GitOps', cmd:
      `argocd app create ${name}-prod \\\n  --repo https://github.com/org/${name} \\\n  --path overlays/prod \\\n  --dest-namespace ${name}-prod \\\n  --sync-policy automated \\\n  --self-heal --auto-prune` });
  }

  if (req.keda && req.keda.enabled) {
    cards.push({ env: 'info', title: 'Install KEDA', cmd:
      `helm repo add kedacore https://kedacore.github.io/charts\nhelm repo update\nhelm install keda kedacore/keda \\\n  --namespace keda --create-namespace` });
    cards.push({ env: 'info', title: 'Check KEDA ScaledObject', cmd:
      `kubectl get scaledobject -n ${name}-prod\nkubectl describe scaledobject/${name} -n ${name}-prod` });
  }
  if (req.secrets && req.secrets.provider === 'external-secrets') {
    cards.push({ env: 'info', title: 'Install ESO', cmd:
      `helm repo add external-secrets https://charts.external-secrets.io\nhelm install external-secrets \\\n  external-secrets/external-secrets \\\n  -n external-secrets --create-namespace` });
  }
  if (req.secrets && req.secrets.provider === 'vault') {
    cards.push({ env: 'info', title: 'Install Vault Secrets Operator', cmd:
      `helm repo add hashicorp https://helm.releases.hashicorp.com\nhelm install vault-secrets-operator \\\n  hashicorp/vault-secrets-operator \\\n  -n vault-secrets-operator --create-namespace` });
  }

  cards.forEach(card => {
    const div = document.createElement('div');
    div.className = 'cmd-card';

    const titleEl = document.createElement('div');
    titleEl.className = 'cmd-card-title';
    titleEl.textContent = card.title;

    const envEl = document.createElement('span');
    envEl.className = `cmd-card-env ${card.env}`;
    envEl.textContent = card.env;

    const encoded = encodeURIComponent(card.cmd);
    const btn = document.createElement('button');
    btn.className = 'cmd-copy';
    btn.textContent = 'Copy';
    btn.onclick = () => copyToClipboard(decodeURIComponent(encoded), btn);

    const cmdEl = document.createElement('div');
    cmdEl.className = 'cmd-code';
    // Render command as plain text to avoid HTML injection / broken tags
    cmdEl.textContent = card.cmd;

    div.appendChild(titleEl);
    div.appendChild(envEl);
    div.appendChild(btn);
    div.appendChild(cmdEl);
    body.appendChild(div);
  });
}

function hlCmd(code) {
  let h = code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  h = h.replace(/(#[^\n]*)/g, '<span class="cc">$1</span>');
  h = h.replace(/\b(helm|kubectl|flux|argocd|kustomize|docker|git)\b/g, '<span class="cmd">$1</span>');
  // Flags like --namespace, --wait, --timeout
  h = h.replace(/\b(--[a-zA-Z0-9\-]+)\b/g, '<span class="cf">$1</span>');
  // URLs and paths
  h = h.replace(/((?:https?:\/\/|\.\/|\.\.|\/)[^\s&<]+)/g, '<span class="cp">$1</span>');
  return h;
}

// ── Command Drawer ─────────────────────────────────────
function toggleCmdDrawer() {
  cmdDrawerOpen = !cmdDrawerOpen;
  document.getElementById('cmd-drawer').classList.toggle('collapsed', !cmdDrawerOpen);
  document.getElementById('cmd-chevron').textContent = cmdDrawerOpen ? '▲' : '▼';
}

// ── Download ZIP ───────────────────────────────────────
async function downloadZip() {
  const btn = document.getElementById('btn-download');
  btn.disabled = true;
  const orig = btn.innerHTML;
  btn.innerHTML = '<span class="spinner" style="border-color:rgba(0,212,255,.2);border-top-color:var(--accent)"></span> Packing...';

  try {
    const req = collectRequest();
    const resp = await fetch('/api/download', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req)
    });

    if (!resp.ok) throw new Error(await resp.text());

    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const name = document.getElementById('app-name').value.trim() || 'my-app';
    a.href = url;
    a.download = `${name}-${currentMode}-blueprint.zip`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('✓ ZIP downloaded');
  } catch (err) {
    showToast('✗ ' + err.message, true);
  } finally {
    btn.disabled = false;
    btn.innerHTML = orig;
  }
}

// ── Toast ──────────────────────────────────────────────
let toastTimer;
function showToast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast' + (isError ? ' error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.classList.add('hidden'); }, 3000);
}

// ── Init ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  updateKedaTrigger('kafka');
  
  // Setup Istio AuthzPolicy toggle listener
  document.getElementById('istio-ap').addEventListener('change', updateIstiAuthzPolicy);
});

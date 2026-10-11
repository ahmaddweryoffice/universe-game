import { importKey, unseal, seal, progressSlot, toBase64Url } from './crypto.mjs';

const gate = document.getElementById('gate');
const status = document.getElementById('unlock-status');
const form = document.getElementById('unlock-form');
const field = document.getElementById('invitation-key');
const button = document.getElementById('unlock-button');
function consumeFragment() {
  const key = new URLSearchParams(location.hash.slice(1)).get('key');
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  return key;
}
let scannedKey = consumeFragment();
const decoder = new TextDecoder();
const neutralTitle = document.title;
let unlocking = false;

function resourcePath(id) {
  if (!/^[a-f0-9]{32}$/.test(id)) throw new Error('Invalid resource');
  return `${id}.bin`;
}

async function fetchBytes(path) {
  const response = await fetch(path, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!response.ok) throw new Error('Unavailable');
  return response.arrayBuffer();
}

async function unlock(keyText) {
  if (unlocking) return;
  unlocking = true;
  button.disabled = true;
  status.textContent = 'Opening your invitation…';
  field.value = '';
  const urls = new Set();
  const mount = document.createElement('div');
  let stylesheet;
  try {
    const key = await importKey(keyText);
    const response = await fetch('envelope.json', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!response.ok) throw new Error('Unavailable');
    const envelope = await response.json();
    if (envelope.version !== 1) throw new Error('Unsupported version');
    const id = envelope.manifest;
    const manifest = JSON.parse(decoder.decode(await unseal(await fetchBytes(resourcePath(id)), key, id)));
    if (manifest.version !== 1 || !manifest.entry || !manifest.style || !manifest.content || !manifest.assets) throw new Error('Invalid manifest');
    const slot = await progressSlot(keyText);
    keyText = null;
    scannedKey = null;
    const pendingAssets = new Map();
    const makeUrl = (bytes, type) => {
      const url = URL.createObjectURL(new Blob([bytes], { type }));
      urls.add(url);
      return url;
    };
    const decryptResource = async resource => unseal(await fetchBytes(resourcePath(resource.id)), key, resource.id);
    const runtime = {
      async asset(name) {
        const asset = manifest.assets[name];
        if (!asset) throw new Error('Asset unavailable');
        if (!pendingAssets.has(name)) pendingAssets.set(name, decryptResource(asset).then(bytes => makeUrl(bytes, asset.type)).catch(error => { pendingAssets.delete(name); throw error; }));
        return pendingAssets.get(name);
      },
      async loadProgress() {
        try {
          const value = localStorage.getItem(slot);
          if (!value) return null;
          const data = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
          return JSON.parse(decoder.decode(await unseal(data, key, 'progress/v1')));
        } catch { return null; }
      },
      async saveProgress(value) {
        const data = await seal(new TextEncoder().encode(JSON.stringify(value)), key, 'progress/v1');
        try { localStorage.setItem(slot, toBase64Url(data)); return true; } catch { return false; }
      },
      clearProgress() { try { localStorage.removeItem(slot); } catch {} },
      lock() { location.replace(location.pathname); }
    };
    const [entry, style, content] = await Promise.all([decryptResource(manifest.entry), decryptResource(manifest.style), decryptResource(manifest.content)]);
    stylesheet = document.createElement('link');
    stylesheet.rel = 'stylesheet';
    stylesheet.href = makeUrl(style, 'text/css');
    const styleReady = new Promise((resolve, reject) => { stylesheet.onload = resolve; stylesheet.onerror = reject; });
    document.head.append(stylesheet);
    const app = await import(makeUrl(entry, 'text/javascript'));
    await styleReady;
    await app.start({ root: mount, content: JSON.parse(decoder.decode(content)), runtime });
    document.body.append(...mount.childNodes);
    gate.remove();
    window.addEventListener('pagehide', () => { for (const url of urls) URL.revokeObjectURL(url); }, { once: true });
  } catch {
    stylesheet?.remove();
    document.title = neutralTitle;
    for (const url of urls) URL.revokeObjectURL(url);
    status.textContent = 'This invitation could not be opened. Check your key or scan the ticket again.';
    button.disabled = false;
    unlocking = false;
    scannedKey = null;
  }
}

form.addEventListener('submit', event => { event.preventDefault(); void unlock(field.value.trim()); });
window.addEventListener('hashchange', () => {
  const key = consumeFragment();
  if (key && !unlocking) void unlock(key);
});
if (scannedKey) void unlock(scannedKey);

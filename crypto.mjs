const MAGIC = new Uint8Array([80, 82, 73, 86, 1, 0, 0, 0]);
const encoder = new TextEncoder();

export function toBase64Url(bytes) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function decodeKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('Invalid key');
  const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='), c => c.charCodeAt(0));
  if (bytes.length !== 32 || toBase64Url(bytes) !== value) throw new Error('Invalid key');
  return bytes;
}

export function newKey() {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export function importKey(value) {
  return crypto.subtle.importKey('raw', decodeKey(value), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

function associatedData(resource) {
  if (typeof resource !== 'string' || !resource || resource.length > 200) throw new Error('Invalid resource');
  return encoder.encode(`private-gift/v1/${resource}`);
}

export async function seal(bytes, key, resource) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: associatedData(resource), tagLength: 128 }, key, bytes);
  const result = new Uint8Array(MAGIC.length + iv.length + ciphertext.byteLength);
  result.set(MAGIC);
  result.set(iv, MAGIC.length);
  result.set(new Uint8Array(ciphertext), MAGIC.length + iv.length);
  return result;
}

export async function unseal(bytes, key, resource) {
  const data = new Uint8Array(bytes);
  if (data.length < 36 || MAGIC.some((v, i) => data[i] !== v)) throw new Error('Invalid payload');
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(8, 20), additionalData: associatedData(resource), tagLength: 128 }, key, data.slice(20));
}

export async function progressSlot(keyText) {
  const hash = await crypto.subtle.digest('SHA-256', decodeKey(keyText));
  return `private-progress:${toBase64Url(hash).slice(0, 22)}`;
}

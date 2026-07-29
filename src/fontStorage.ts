// Keep the pre-release database name so existing uploaded fonts remain available.
const DATABASE_NAME = "opsshell-local-assets";
const STORE_NAME = "fonts";
const ACTIVE_FONT_KEY = "terminal-font";
const CUSTOM_FONT_FAMILY = "VPShell Custom Font";
const MAX_FONT_BYTES = 12 * 1024 * 1024;

function openDatabase() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("无法打开本机字体存储"));
  });
}

async function registerFont(blob: Blob) {
  const font = new FontFace(CUSTOM_FONT_FAMILY, await blob.arrayBuffer());
  const loaded = await font.load();
  document.fonts.add(loaded);
  return CUSTOM_FONT_FAMILY;
}

export async function saveAndRegisterCustomFont(file: File) {
  const supportedExtension = /\.(ttf|otf|woff2?)$/i.test(file.name);
  if (!supportedExtension || file.size === 0 || file.size > MAX_FONT_BYTES) {
    throw new Error("字体必须是 12 MB 以内的 TTF、OTF、WOFF 或 WOFF2 文件");
  }
  const family = await registerFont(file);
  const database = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(file, ACTIVE_FONT_KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("无法保存本机字体"));
  });
  database.close();
  return family;
}

export async function loadStoredCustomFont() {
  const database = await openDatabase();
  const blob = await new Promise<Blob | undefined>((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readonly");
    const request = transaction.objectStore(STORE_NAME).get(ACTIVE_FONT_KEY);
    request.onsuccess = () => resolve(request.result as Blob | undefined);
    request.onerror = () => reject(request.error ?? new Error("无法读取本机字体"));
  });
  database.close();
  return blob ? registerFont(blob) : undefined;
}

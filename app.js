import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, signOut }
  from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  initializeFirestore, persistentLocalCache, persistentMultipleTabManager,
  doc, getDoc, getDocFromServer, setDoc, deleteDoc, collection, onSnapshot, serverTimestamp, writeBatch,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { firebaseConfig } from "./firebase-config.js";

// ---- 設定 ----
const PBKDF2_ITER = 600000;          // 鍵導出の反復回数（OWASP 推奨値）
const IDLE_LOCK_MS = 5 * 60 * 1000;  // 無操作で自動ロックするまでの時間
const HIDDEN_LOCK_MS = 60 * 1000;    // バックグラウンドに回ってから自動ロックするまでの時間
const CLIPBOARD_CLEAR_MS = 30 * 1000;
const CAT_DOC = "_categories";       // items コレクション内の、カテゴリー一覧を保存する特別なドキュメント
const RESERVED_CATS = ["すべて", "未分類"];

const $ = (s, root = document) => root.querySelector(s);

// ---- 暗号化（Web Crypto: PBKDF2-SHA256 → AES-256-GCM） ----
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

async function encryptJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}

async function decryptJSON(key, { iv, ct }) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(ct));
  return JSON.parse(dec.decode(pt));
}

function generatePassword(length = 20) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_=+?";
  const limit = Math.floor(2 ** 32 / chars.length) * chars.length; // 偏りをなくすための棄却サンプリング
  const buf = new Uint32Array(1);
  let out = "";
  while (out.length < length) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) out += chars[buf[0] % chars.length];
  }
  return out;
}

// ---- 画面状態 ----
let auth, db;
let user = null;
let key = null;        // 復号鍵（メモリ上のみ）
let meta = null;       // users/{uid} ドキュメント（salt と検証用データ）
let items = [];
let storedCats = [];   // 明示的に登録されたカテゴリー（空のものも含む）
let unsubscribe = null;
let currentCat = null; // null = すべて, "" = 未分類, それ以外 = カテゴリー名

function show(view) {
  for (const v of ["config", "login", "unlock", "main"]) $("#v-" + v).hidden = v !== view;
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2500);
}

// ---- 起動 ----
if (!firebaseConfig.apiKey || firebaseConfig.apiKey.startsWith("YOUR_")) {
  show("config");
} else {
  const app = initializeApp(firebaseConfig);
  auth = getAuth(app);
  db = initializeFirestore(app, {
    localCache: persistentLocalCache({ tabManager: persistentMultipleTabManager() }),
  });
  onAuthStateChanged(auth, async (u) => {
    lock(false);
    user = u;
    meta = null;
    if (!u) return show("login");
    await prepareUnlock();
  });
}

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});

// ---- ログイン ----
$("#f-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#login-error");
  const btn = e.submitter;
  err.textContent = "";
  btn.disabled = true;
  try {
    await signInWithEmailAndPassword(auth, $("#login-email").value.trim(), $("#login-pass").value);
    $("#login-pass").value = "";
  } catch (ex) {
    err.textContent = ["auth/invalid-credential", "auth/wrong-password", "auth/user-not-found", "auth/invalid-email"].includes(ex.code)
      ? "メールアドレスかパスワードが違います"
      : ex.code === "auth/too-many-requests" ? "試行回数が多すぎます。しばらく待ってください"
      : "ログインできませんでした（" + ex.code + "）";
  } finally {
    btn.disabled = false;
  }
});

document.querySelectorAll(".btn-logout").forEach((b) =>
  b.addEventListener("click", () => { lock(false); signOut(auth); }));

// ---- マスターパスワード ----
const metaRef = () => doc(db, "users", user.uid);
let setupMode = false;

async function prepareUnlock() {
  $("#unlock-error").textContent = "";
  try {
    let snap = await getDoc(metaRef());
    // 「未設定」と判定する前に必ずサーバーで確認する（オフラインキャッシュの誤判定で上書きしないため）
    if (!snap.exists()) snap = await getDocFromServer(metaRef());
    meta = snap.exists() ? snap.data() : null;
  } catch {
    meta = null;
    setUnlockMode(false);
    $("#unlock-error").textContent = "サーバーに接続できません。オンラインで再度開いてください";
    $("#unlock-btn").disabled = true;
    return show("unlock");
  }
  $("#unlock-btn").disabled = false;
  setUnlockMode(!meta);
  show("unlock");
  $("#master").focus();
}

function setUnlockMode(setup) {
  setupMode = setup;
  $("#unlock-title").textContent = setup ? "マスターパスワードの設定" : "ロック解除";
  $("#unlock-desc").textContent = setup
    ? "データを暗号化するためのマスターパスワードを決めてください。"
    : "マスターパスワードを入力してください。";
  $("#unlock-warn").hidden = !setup;
  $("#confirm-wrap").hidden = !setup;
  $("#unlock-btn").textContent = setup ? "設定して開始" : "解除";
}

$("#f-unlock").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#unlock-error");
  const btn = $("#unlock-btn");
  const pw = $("#master").value;
  err.textContent = "";

  if (setupMode) {
    if (pw.length < 8) return (err.textContent = "8文字以上にしてください");
    if (pw !== $("#master2").value) return (err.textContent = "確認用と一致しません");
  }

  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = "処理中…";
  try {
    if (setupMode) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const k = await deriveKey(pw, salt, PBKDF2_ITER);
      const newMeta = { salt: b64(salt), iter: PBKDF2_ITER, check: await encryptJSON(k, { v: "ok" }) };
      await setDoc(metaRef(), { ...newMeta, createdAt: serverTimestamp() });
      meta = newMeta;
      key = k;
    } else {
      const k = await deriveKey(pw, unb64(meta.salt), meta.iter);
      try {
        await decryptJSON(k, meta.check);
      } catch {
        err.textContent = "マスターパスワードが違います";
        return;
      }
      key = k;
    }
    $("#master").value = "";
    $("#master2").value = "";
    startMain();
  } catch (ex) {
    err.textContent = "エラーが発生しました（" + (ex.code || ex.message) + "）";
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

// ---- メイン（一覧・同期） ----
function startMain() {
  show("main");
  $("#search").value = "";
  render();
  const myKey = key;
  unsubscribe = onSnapshot(itemsCol(), async (snap) => {
    let cats = [];
    const list = (await Promise.all(snap.docs.map(async (d) => {
      try {
        const data = await decryptJSON(myKey, d.data());
        if (d.id === CAT_DOC) { cats = data.names || []; return null; }
        return { id: d.id, ...data };
      } catch {
        return d.id === CAT_DOC ? null : { id: d.id, site: "（復号できないデータ）", broken: true };
      }
    }))).filter(Boolean);
    if (key !== myKey) return; // 復号中にロックされた
    storedCats = cats;
    items = list.sort((a, b) => (a.site || "").localeCompare(b.site || "", "ja"));
    render();
  }, (ex) => toast("同期エラー: " + ex.code));
  resetIdle();
}

function lock(showUnlock = true) {
  key = null;
  items = [];
  storedCats = [];
  if (unsubscribe) unsubscribe();
  unsubscribe = null;
  clearTimeout(idleTimer);
  for (const d of document.querySelectorAll("dialog[open]")) d.close();
  $("#list").replaceChildren();
  if (showUnlock && user && meta) {
    setUnlockMode(false);
    $("#unlock-error").textContent = "";
    show("unlock");
  }
}

$("#btn-lock").addEventListener("click", () => lock());
$("#search").addEventListener("input", render);

function safeUrl(raw) {
  if (!raw) return null;
  const s = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : "https://" + raw;
  try {
    const u = new URL(s);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

const itemsCol = () => collection(db, "users", user.uid, "items");
const sortJa = (arr) => arr.sort((a, b) => a.localeCompare(b, "ja"));

// 登録済みカテゴリー＋項目に付いているカテゴリー
function categoryList() {
  return sortJa([...new Set([...storedCats, ...items.map((it) => it.category || "")].filter(Boolean))]);
}

// 一括書き込み用：項目を暗号化してバッチに追加（id なしなら新規）
async function queueItem(batch, { id, broken, ...data }) {
  const ref = id ? doc(itemsCol(), id) : doc(itemsCol());
  batch.set(ref, { ...(await encryptJSON(key, data)), updatedAt: serverTimestamp() });
}

async function queueCats(batch, names) {
  const list = sortJa([...new Set(names.filter(Boolean))]);
  batch.set(doc(itemsCol(), CAT_DOC), { ...(await encryptJSON(key, { names: list })), updatedAt: serverTimestamp() });
}

// オフラインでも書き込みは端末に反映され、接続時に同期されるので完了を待たない
function commit(batch, what) {
  batch.commit().catch((ex) => toast(`${what}に失敗しました: ${ex.code}`));
}

function validateCatName(name) {
  if (!name) return "名前を入力してください";
  if (RESERVED_CATS.includes(name)) return `「${name}」は使えません`;
  return "";
}

// 長押し（スマホ）・右クリック（PC）で編集画面を開く
function attachCatManage(btn, name) {
  let timer;
  let opened = false;
  const open = () => { opened = true; if (!$("#dlg-cat").open) openCatDialog(name); };
  btn.addEventListener("pointerdown", () => { opened = false; timer = setTimeout(open, 550); });
  for (const ev of ["pointerup", "pointerleave", "pointercancel"]) btn.addEventListener(ev, () => clearTimeout(timer));
  btn.addEventListener("contextmenu", (e) => { e.preventDefault(); clearTimeout(timer); open(); });
  // 長押しで開いた直後の click で絞り込みが切り替わらないようにする
  btn.addEventListener("click", (e) => { if (opened) { opened = false; e.stopImmediatePropagation(); } }, { capture: true });
}

function renderCategories() {
  const names = categoryList();
  const hasNone = items.some((it) => !it.category);
  // 選択中のカテゴリーが無くなったら「すべて」に戻す
  if (currentCat !== null && !(currentCat === "" ? hasNone : names.includes(currentCat))) currentCat = null;

  const chip = (label, value, count) => {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    const c = document.createElement("span");
    c.className = "count";
    c.textContent = count;
    b.append(c);
    b.setAttribute("aria-pressed", String(currentCat === value));
    b.addEventListener("click", () => {
      // 選択中のカテゴリーをもう一度押すと編集画面
      if (value && currentCat === value) return openCatDialog(value);
      currentCat = value;
      render();
    });
    if (value) {
      b.title = "もう一度押す・長押し・右クリックで名前の変更／削除";
      attachCatManage(b, value);
    }
    return b;
  };
  const chips = [chip("すべて", null, items.length)];
  for (const n of names) chips.push(chip(n, n, items.filter((it) => it.category === n).length));
  if (hasNone && names.length) chips.push(chip("未分類", "", items.filter((it) => !it.category).length));
  const add = document.createElement("button");
  add.type = "button";
  add.className = "add-cat";
  add.textContent = "＋ カテゴリー";
  add.addEventListener("click", () => openCatDialog(null));
  chips.push(add);
  $("#cats").replaceChildren(...chips);

  $("#cat-options").replaceChildren(...names.map((n) => Object.assign(document.createElement("option"), { value: n })));
}

function render() {
  renderCategories();
  const q = $("#search").value.trim().toLowerCase();
  const shown = items.filter((it) =>
    (currentCat === null || (it.category || "") === currentCat) &&
    (!q || [it.site, it.username, it.url, it.memo, it.category].some((v) => (v || "").toLowerCase().includes(q))));
  const tpl = $("#tpl-item");
  $("#list").replaceChildren(...shown.map((it) => {
    const li = tpl.content.firstElementChild.cloneNode(true);
    $(".site-name", li).textContent = it.site || "(名称なし)";
    if (it.category && currentCat === null) {
      const cat = $(".cat", li);
      cat.textContent = it.category;
      cat.hidden = false;
    }
    $(".user", li).textContent = it.username || "";
    const body = $(".item-body", li);
    $(".item-title", li).addEventListener("click", () => { body.hidden = !body.hidden; });

    const copyUser = $(".btn-copy-user", li);
    const copyPw = $(".btn-copy-pw", li);
    copyUser.disabled = !it.username;
    copyPw.disabled = !it.password;
    copyUser.addEventListener("click", () => copy(it.username, "ID"));
    copyPw.addEventListener("click", () => copy(it.password, "パスワード"));

    const pwEl = $(".pw", li);
    const showBtn = $(".btn-show", li);
    if (!it.password) { pwEl.textContent = "（未設定）"; showBtn.hidden = true; }
    showBtn.addEventListener("click", () => {
      const visible = showBtn.textContent === "隠す";
      pwEl.textContent = visible ? "••••••••" : it.password;
      showBtn.textContent = visible ? "表示" : "隠す";
    });

    const href = safeUrl(it.url);
    if (href) { const a = $(".url", li); a.href = href; a.textContent = it.url; }
    else $(".url-row", li).hidden = true;
    if (it.memo) $(".memo", li).textContent = it.memo;
    else $(".memo-row", li).hidden = true;

    const editBtn = $(".btn-edit", li);
    if (it.broken) editBtn.hidden = true;
    editBtn.addEventListener("click", () => openEdit(it));
    return li;
  }));
  const empty = $("#empty");
  empty.hidden = shown.length > 0;
  empty.textContent = items.length ? (q ? "該当するものがありません" : "このカテゴリーには登録がありません") : "まだ登録がありません。「＋ 追加」から登録してください。";
}

// ---- コピー ----
let clipTimer;
async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return toast("コピーできませんでした");
  }
  toast(`${label}をコピーしました（30秒後にクリア）`);
  clearTimeout(clipTimer);
  clipTimer = setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), CLIPBOARD_CLEAR_MS);
}

// ---- 追加・編集 ----
const dlg = $("#dlg-edit");
let editingId = null;

function openEdit(it = null) {
  editingId = it ? it.id : null;
  $("#edit-title").textContent = it ? "編集" : "追加";
  $("#e-site").value = it?.site || "";
  $("#e-cat").value = it ? it.category || "" : currentCat || ""; // 新規は表示中のカテゴリーを初期値に
  $("#e-url").value = it?.url || "";
  $("#e-user").value = it?.username || "";
  $("#e-pass").value = it?.password || "";
  $("#e-pass").type = "password";
  $("#e-memo").value = it?.memo || "";
  $("#e-delete").hidden = !it;
  dlg.showModal();
  if (!it) $("#e-site").focus();
}

$("#btn-add").addEventListener("click", () => openEdit());
$("#e-cancel").addEventListener("click", () => dlg.close());
$("#e-toggle").addEventListener("click", () => {
  const p = $("#e-pass");
  p.type = p.type === "password" ? "text" : "password";
});
$("#e-gen").addEventListener("click", () => {
  const p = $("#e-pass");
  if (p.value && !confirm("今のパスワードを新しく生成したものに置き換えますか？")) return;
  p.value = generatePassword();
  p.type = "text";
});

$("#f-edit").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!key) return;
  const cat = $("#e-cat").value.trim();
  const data = {
    site: $("#e-site").value.trim(),
    category: cat === "未分類" ? "" : cat,
    url: $("#e-url").value.trim(),
    username: $("#e-user").value.trim(),
    password: $("#e-pass").value,
    memo: $("#e-memo").value,
  };
  const save = $("#e-save");
  save.disabled = true;
  try {
    const batch = writeBatch(db);
    await queueItem(batch, { id: editingId, ...data });
    // 新しいカテゴリー名なら一覧にも登録（項目が0件になっても残るように）
    if (data.category && !storedCats.includes(data.category)) await queueCats(batch, [...storedCats, data.category]);
    commit(batch, "保存");
    dlg.close();
    toast("保存しました");
  } finally {
    save.disabled = false;
  }
});

$("#e-delete").addEventListener("click", () => {
  if (!editingId || !confirm(`「${$("#e-site").value}」を削除しますか？`)) return;
  deleteDoc(doc(db, "users", user.uid, "items", editingId)).catch((ex) => toast("削除に失敗しました: " + ex.code));
  dlg.close();
  toast("削除しました");
});

// ---- カテゴリーの追加・名前変更・削除 ----
const dlgCat = $("#dlg-cat");
let catEditing = null; // null = 新規追加

function openCatDialog(name) {
  catEditing = name;
  const count = name ? items.filter((it) => it.category === name).length : 0;
  $("#cat-title").textContent = name ? "カテゴリーの編集" : "カテゴリーを追加";
  $("#cat-info").textContent = name ? `${count}件の項目が入っています。名前を変えると全項目に反映されます。` : "";
  $("#cat-info").hidden = !name;
  $("#cat-name").value = name || "";
  $("#cat-error").textContent = "";
  $("#cat-delete").hidden = !name;
  $("#cat-save").textContent = name ? "名前を変更" : "追加";
  dlgCat.showModal();
  $("#cat-name").focus();
}

$("#cat-cancel").addEventListener("click", () => dlgCat.close());

$("#f-cat").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!key) return;
  const newName = $("#cat-name").value.trim();
  const err = validateCatName(newName);
  if (err) return ($("#cat-error").textContent = err);
  const exists = categoryList().includes(newName);
  const old = catEditing;

  if (old === null) {
    if (exists) return ($("#cat-error").textContent = "同じ名前のカテゴリーがあります");
    const batch = writeBatch(db);
    await queueCats(batch, [...storedCats, newName]);
    commit(batch, "追加");
    currentCat = newName;
    toast(`「${newName}」を追加しました`);
  } else {
    if (newName === old) return dlgCat.close();
    if (exists && !confirm(`「${newName}」は既にあります。「${old}」の項目を「${newName}」にまとめますか？`)) return;
    const batch = writeBatch(db);
    for (const it of items) if (it.category === old) await queueItem(batch, { ...it, category: newName });
    await queueCats(batch, [...storedCats.filter((n) => n !== old), newName]);
    commit(batch, "名前の変更");
    if (currentCat === old) currentCat = newName;
    toast(`「${old}」を「${newName}」に変更しました`);
  }
  dlgCat.close();
});

$("#cat-delete").addEventListener("click", async () => {
  if (!key || !catEditing) return;
  const name = catEditing;
  const targets = items.filter((it) => it.category === name);
  const msg = targets.length
    ? `カテゴリー「${name}」を削除しますか？\n中の${targets.length}件は「未分類」に移ります（項目は消えません）。`
    : `カテゴリー「${name}」を削除しますか？`;
  if (!confirm(msg)) return;
  const batch = writeBatch(db);
  for (const it of targets) await queueItem(batch, { ...it, category: "" });
  await queueCats(batch, storedCats.filter((n) => n !== name));
  commit(batch, "削除");
  if (currentCat === name) currentCat = null;
  dlgCat.close();
  toast(`「${name}」を削除しました`);
});

// ---- 自動ロック ----
let idleTimer;
let hiddenAt = 0;
function resetIdle() {
  clearTimeout(idleTimer);
  if (key) idleTimer = setTimeout(() => lock(), IDLE_LOCK_MS);
}
for (const ev of ["pointerdown", "keydown", "scroll"]) addEventListener(ev, resetIdle, { passive: true });
document.addEventListener("visibilitychange", () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (key && Date.now() - hiddenAt > HIDDEN_LOCK_MS) lock();
  else resetIdle();
});

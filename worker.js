// Bookshelf: Randy and Lisa's home book collection.
//
// One Cloudflare Worker serves the page, the shelf API, and the
// installable-app files (manifest, service worker, icon). Data lives
// in the D1 database "bookshelf" (binding DB). Books are loaded by an
// import job, not through this app. The app only reads them and
// records read marks, star ratings, reader labels, title and author
// edits, and custom lists.
//
// The page is unlisted on purpose: it is never linked or indexed, it
// asks search engines to stay away, and once the SITE_PASSCODE secret
// is set, the first visit from a device needs the passcode. A correct
// code earns the device a remembered token, so the code is only
// entered once per device. Until the secret is set the gate is
// inactive and the site is open, so setting the secret is what
// switches the gate on.
//
// Secrets: SITE_PASSCODE is a Worker secret, never in code. No other
// secret is needed in v1.

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function ipHash(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const day = new Date().toISOString().slice(0, 10);
  return sha256Hex(ip + "|" + day + "|bookshelf");
}

async function readJson(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 20000) return null;
  try {
    return await request.json();
  } catch (err) {
    return null;
  }
}

// Passcode gate: the first visit from a device shows a code box
// instead of the shelves. The code lives as the SITE_PASSCODE
// secret, never in code. A correct code earns the device a random
// token; the cookie holds the token, never the code, and only the
// token's hash is stored (device_tokens, one year). Until the secret
// is set the gate is inactive and the site behaves as an open page,
// so setting the secret is what switches the gate on. The cookie name
// differs from the Watch List gate on purpose, so the two gates stay
// independent.
const GATE_COOKIE = "bs_auth";
const GATE_MAX_AGE = 365 * 24 * 60 * 60; // one year, in seconds

function gateActive(env) {
  return Boolean(env.SITE_PASSCODE);
}

function parseCookies(request) {
  const out = {};
  const header = request.headers.get("Cookie") || "";
  header.split(";").forEach(function (part) {
    const at = part.indexOf("=");
    if (at > 0) out[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  });
  return out;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function gateUnlocked(env, request) {
  if (!gateActive(env)) return true;
  try {
    const token = parseCookies(request)[GATE_COOKIE];
    if (!token || token.length < 20) return false;
    const hash = await sha256Hex(token);
    const row = await env.DB.prepare(
      "SELECT expires_at FROM device_tokens WHERE token_hash = ?"
    )
      .bind(hash)
      .first();
    if (!row) return false;
    return row.expires_at > new Date().toISOString();
  } catch (err) {
    // A lookup failure fails closed: the gate page, not the shelves.
    return false;
  }
}

async function handleUnlock(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") {
    return jsonResponse({ ok: false, error: "That did not come through properly." }, 400);
  }
  if (!gateActive(env)) {
    return jsonResponse({ ok: false, error: "The passcode is not set up yet." }, 503);
  }
  const hash = await ipHash(request);
  // Brute-force guard: five wrong guesses per hour per sender, then
  // the door stays shut until the hour passes.
  const attempts = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM unlock_attempts WHERE ip_hash = ? AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 hour')"
  )
    .bind(hash)
    .first();
  if (attempts && attempts.n >= 5) {
    return jsonResponse({ ok: false, error: "Too many wrong codes. Try again later." }, 429);
  }
  const code = String(body.code || "");
  const match =
    code &&
    timingSafeEqual(await sha256Hex(code), await sha256Hex(env.SITE_PASSCODE));
  if (!match) {
    await env.DB.prepare(
      "INSERT INTO unlock_attempts (ip_hash, created_at) VALUES (?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))"
    )
      .bind(hash)
      .run();
    return jsonResponse({ ok: false, error: "That code did not match." }, 403);
  }
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let token = "";
  bytes.forEach(function (b) {
    token += b.toString(16).padStart(2, "0");
  });
  const tokenHash = await sha256Hex(token);
  const expires = new Date(Date.now() + GATE_MAX_AGE * 1000).toISOString();
  await env.DB.prepare(
    "INSERT INTO device_tokens (token_hash, created_at, expires_at) VALUES (?, strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?)"
  )
    .bind(tokenHash, expires)
    .run();
  // Prune expired tokens and old attempts while here.
  await env.DB.prepare(
    "DELETE FROM device_tokens WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%SZ','now')"
  ).run();
  await env.DB.prepare(
    "DELETE FROM unlock_attempts WHERE created_at < strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day')"
  ).run();
  const resp = jsonResponse({ ok: true });
  resp.headers.append(
    "Set-Cookie",
    GATE_COOKIE + "=" + token + "; Max-Age=" + GATE_MAX_AGE + "; Path=/; HttpOnly; Secure; SameSite=Lax"
  );
  return resp;
}

// The gate page: a bare code box, styled like the app. It carries no
// shelf data and no app script, so a stranger sees nothing but the box.
function gateHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Bookshelf</title>
<meta name="theme-color" content="#2b1d12">
<link rel="icon" type="image/svg+xml" href="/icon.svg">
<style>
  body { margin: 0; background: #17100a; color: #f2e8d5; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 420px; margin: 18vh auto 0; padding: 0 20px; text-align: center; }
  h1 { font-size: 28px; margin: 0 0 8px; color: #f7ecd7; }
  p { color: #c9b69a; font-size: 15px; line-height: 1.5; }
  form { display: flex; gap: 8px; margin-top: 18px; }
  input { flex: 1; min-width: 0; padding: 11px 12px; font-size: 16px; border-radius: 8px; border: 1px solid #4a3220; background: #241a10; color: #f2e8d5; }
  button { padding: 11px 16px; font-size: 15px; font-weight: 600; border-radius: 8px; border: 1px solid #d9a441; background: #d9a441; color: #241708; cursor: pointer; }
  #gateError { color: #f87171; }
</style>
</head>
<body>
<main>
<h1>Bookshelf</h1>
<p>Enter the passcode to open the bookshelf. You only need it once on this device.</p>
<form id="gateForm">
<input type="password" id="gateCode" autocomplete="current-password" placeholder="Passcode" aria-label="Passcode">
<button type="submit">Open the shelves</button>
</form>
<p id="gateError" hidden></p>
</main>
<script>
document.getElementById("gateForm").addEventListener("submit", function (e) {
  e.preventDefault();
  var code = document.getElementById("gateCode").value;
  var err = document.getElementById("gateError");
  err.hidden = true;
  fetch("/api/unlock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: code }) })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d && d.ok) { window.location.reload(); }
      else { err.textContent = (d && d.error) || "That did not work. Try again."; err.hidden = false; }
    })
    .catch(function () { err.textContent = "Could not reach the site. Try again."; err.hidden = false; });
});
</script>
</body>
</html>`;
}

// ---- API helpers ----

// The books table stores genres and formats as JSON array text
// (empty string when none). The client wants real arrays.
function parseJsonArray(value) {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) return value.map(function (v) { return String(v); }).filter(Boolean);
  const text = String(value).trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed.map(function (v) { return String(v); }).filter(Boolean);
    if (typeof parsed === "string" && parsed) return [parsed];
    return [];
  } catch (err) {
    // Not JSON after all: treat a comma separated string as a list.
    return text.split(",").map(function (v) { return v.trim(); }).filter(Boolean);
  }
}

function validId(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : 0;
}

function todayUtc() {
  return new Date().toISOString().slice(0, 10);
}

function badBody() {
  return jsonResponse({ ok: false, error: "That did not come through properly." }, 400);
}

// Title and author keys use the same normalization as the seed import:
// lowercase, a leading "the " dropped from titles, every run of
// non-alphanumeric characters replaced with one space, spaces collapsed.
function titleKeyOf(title) {
  return String(title).toLowerCase().replace(/^the\s+/, "").replace(/[^a-z0-9]+/g, " ").replace(/\s+/g, " ").trim();
}

function authorKeyOf(author) {
  return String(author).toLowerCase().replace(/[^a-z0-9]+/g, " ").replace(/\s+/g, " ").trim();
}

// Dropbox file names may not contain \ / : ? * " < > | or control
// characters. The standardized name is "Title - Author" plus the
// row's current file extension, capped at 200 characters before the
// extension so the name always fits.
function sanitizeDropboxName(name) {
  return String(name).replace(/[\\/:?*"<>|\x00-\x1f\x7f]/g, "").replace(/\s+/g, " ").trim().slice(0, 200);
}

function standardizedFilename(title, author, filename) {
  const dot = String(filename || "").lastIndexOf(".");
  const ext = dot > 0 ? String(filename).slice(dot) : "";
  let base = sanitizeDropboxName(author ? title + " - " + author : title);
  if (!base) base = "Untitled";
  return base + ext;
}

// ---- API handlers ----

async function handleList(env) {
  const bookRes = await env.DB.prepare(
    "SELECT * FROM books ORDER BY title_key ASC, author_key ASC, id ASC"
  ).all();
  const books = (bookRes.results || []).map(function (row) {
    row.genres = parseJsonArray(row.genres);
    row.formats = parseJsonArray(row.formats);
    return row;
  });
  const listRes = await env.DB.prepare(
    "SELECT id, name FROM lists ORDER BY id ASC"
  ).all();
  const itemRes = await env.DB.prepare(
    "SELECT list_id, book_id FROM list_items ORDER BY list_id ASC, position ASC, book_id ASC"
  ).all();
  const itemsByList = {};
  (itemRes.results || []).forEach(function (r) {
    if (!itemsByList[r.list_id]) itemsByList[r.list_id] = [];
    itemsByList[r.list_id].push(r.book_id);
  });
  const lists = (listRes.results || []).map(function (r) {
    return { id: r.id, name: r.name, items: itemsByList[r.id] || [] };
  });
  return jsonResponse({ books: books, lists: lists });
}

async function handleSetRead(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const id = validId(body.id);
  if (!id) return jsonResponse({ ok: false, error: "Bad book id." }, 400);
  if (body.read !== true && body.read !== false && body.read !== 1 && body.read !== 0) {
    return jsonResponse({ ok: false, error: "Read must be true or false." }, 400);
  }
  const read = body.read === true || body.read === 1 ? 1 : 0;
  const row = await env.DB.prepare("SELECT id FROM books WHERE id = ?").bind(id).first();
  if (!row) return jsonResponse({ ok: false, error: "Book not found." }, 404);
  const readOn = read === 1 ? todayUtc() : "";
  await env.DB.prepare(
    "UPDATE books SET is_read = ?, read_on = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?"
  ).bind(read, readOn, id).run();
  return jsonResponse({ ok: true, is_read: read, read_on: readOn });
}

async function handleSetRating(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const id = validId(body.id);
  if (!id) return jsonResponse({ ok: false, error: "Bad book id." }, 400);
  const rating = body.rating;
  if (rating !== null) {
    const okRating =
      typeof rating === "number" &&
      Number.isFinite(rating) &&
      rating >= 0.5 &&
      rating <= 5 &&
      Math.abs(rating * 2 - Math.round(rating * 2)) < 0.000001;
    if (!okRating) {
      return jsonResponse({ ok: false, error: "Rating must be empty or a number from 0.5 to 5 in half steps." }, 400);
    }
  }
  const row = await env.DB.prepare("SELECT id FROM books WHERE id = ?").bind(id).first();
  if (!row) return jsonResponse({ ok: false, error: "Book not found." }, 404);
  await env.DB.prepare(
    "UPDATE books SET rating = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?"
  ).bind(rating, id).run();
  return jsonResponse({ ok: true, rating: rating });
}

async function handleSetReader(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const id = validId(body.id);
  if (!id) return jsonResponse({ ok: false, error: "Bad book id." }, 400);
  const reader = body.reader;
  if (reader !== "Randy" && reader !== "Lisa" && reader !== "All") {
    return jsonResponse({ ok: false, error: "Reader must be Randy, Lisa, or All." }, 400);
  }
  const row = await env.DB.prepare("SELECT id FROM books WHERE id = ?").bind(id).first();
  if (!row) return jsonResponse({ ok: false, error: "Book not found." }, 404);
  await env.DB.prepare(
    "UPDATE books SET reader = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?"
  ).bind(reader, id).run();
  return jsonResponse({ ok: true, reader: reader });
}

async function handleSetTitleAuthor(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const id = validId(body.id);
  if (!id) return jsonResponse({ ok: false, error: "Bad book id." }, 400);
  const title = typeof body.title === "string" ? body.title.trim() : "";
  const author = typeof body.author === "string" ? body.author.trim() : "";
  if (!title) return jsonResponse({ ok: false, error: "Give the book a title." }, 400);
  const row = await env.DB.prepare(
    "SELECT id, title, author, filename, dropbox_path FROM books WHERE id = ?"
  ).bind(id).first();
  if (!row) return jsonResponse({ ok: false, error: "Book not found." }, 404);
  if (title === row.title && author === (row.author || "")) {
    return jsonResponse({ ok: true });
  }
  const titleKey = titleKeyOf(title);
  const authorKey = authorKeyOf(author);
  const dupe = await env.DB.prepare(
    "SELECT id FROM books WHERE title_key = ? AND author_key = ? AND id != ?"
  ).bind(titleKey, authorKey, id).first();
  if (dupe) return jsonResponse({ ok: false, error: "Another book already has that title and author." }, 400);
  await env.DB.prepare(
    "UPDATE books SET title = ?, author = ?, title_key = ?, author_key = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?"
  ).bind(title, author, titleKey, authorKey, id).run();
  // The Worker has no Dropbox access, so the rename itself is left
  // for the nightly job: record it in pending_renames and the job
  // renames old_path to new_filename.
  let newFilename = null;
  if (row.dropbox_path) {
    newFilename = standardizedFilename(title, author, row.filename || "");
    await env.DB.prepare(
      "INSERT INTO pending_renames (book_id, old_path, new_filename, created_at) VALUES (?, ?, ?, datetime('now'))"
    ).bind(id, row.dropbox_path, newFilename).run();
  }
  return jsonResponse({ ok: true, new_filename: newFilename });
}

function cleanListName(value) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, 60);
}

function isUniqueError(err) {
  return err && String(err.message || "").indexOf("UNIQUE") >= 0;
}

async function handleListCreate(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const name = cleanListName(body.name);
  if (!name) return jsonResponse({ ok: false, error: "Give the list a name of 1 to 60 characters." }, 400);
  const dupe = await env.DB.prepare(
    "SELECT id FROM lists WHERE name COLLATE NOCASE = ?"
  ).bind(name).first();
  if (dupe) return jsonResponse({ ok: false, error: "That list already exists." }, 400);
  let id = 0;
  try {
    const result = await env.DB.prepare(
      "INSERT INTO lists (name, created_at) VALUES (?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))"
    ).bind(name).run();
    id = result && result.meta ? result.meta.last_row_id : 0;
  } catch (err) {
    if (isUniqueError(err)) {
      return jsonResponse({ ok: false, error: "That list already exists." }, 400);
    }
    throw err;
  }
  if (!id) {
    const row = await env.DB.prepare(
      "SELECT id FROM lists WHERE name COLLATE NOCASE = ?"
    ).bind(name).first();
    id = row ? row.id : 0;
  }
  return jsonResponse({ ok: true, id: id, name: name });
}

async function handleListRename(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const id = validId(body.id);
  if (!id) return jsonResponse({ ok: false, error: "Bad list id." }, 400);
  const name = cleanListName(body.name);
  if (!name) return jsonResponse({ ok: false, error: "Give the list a name of 1 to 60 characters." }, 400);
  const row = await env.DB.prepare("SELECT id FROM lists WHERE id = ?").bind(id).first();
  if (!row) return jsonResponse({ ok: false, error: "List not found." }, 404);
  const dupe = await env.DB.prepare(
    "SELECT id FROM lists WHERE name COLLATE NOCASE = ? AND id != ?"
  ).bind(name, id).first();
  if (dupe) return jsonResponse({ ok: false, error: "That list already exists." }, 400);
  try {
    await env.DB.prepare("UPDATE lists SET name = ? WHERE id = ?").bind(name, id).run();
  } catch (err) {
    if (isUniqueError(err)) {
      return jsonResponse({ ok: false, error: "That list already exists." }, 400);
    }
    throw err;
  }
  return jsonResponse({ ok: true });
}

async function handleListDelete(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const id = validId(body.id);
  if (!id) return jsonResponse({ ok: false, error: "Bad list id." }, 400);
  const row = await env.DB.prepare("SELECT id FROM lists WHERE id = ?").bind(id).first();
  if (!row) return jsonResponse({ ok: false, error: "List not found." }, 404);
  await env.DB.prepare("DELETE FROM list_items WHERE list_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM lists WHERE id = ?").bind(id).run();
  return jsonResponse({ ok: true });
}

async function handleListAdd(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const listId = validId(body.list_id);
  const bookId = validId(body.book_id);
  if (!listId || !bookId) {
    return jsonResponse({ ok: false, error: "Bad list or book id." }, 400);
  }
  const list = await env.DB.prepare("SELECT id FROM lists WHERE id = ?").bind(listId).first();
  if (!list) return jsonResponse({ ok: false, error: "List not found." }, 400);
  const book = await env.DB.prepare("SELECT id FROM books WHERE id = ?").bind(bookId).first();
  if (!book) return jsonResponse({ ok: false, error: "Book not found." }, 400);
  const existing = await env.DB.prepare(
    "SELECT position FROM list_items WHERE list_id = ? AND book_id = ?"
  ).bind(listId, bookId).first();
  if (existing) return jsonResponse({ ok: true, already: true });
  const maxRow = await env.DB.prepare(
    "SELECT COALESCE(MAX(position), -1) AS m FROM list_items WHERE list_id = ?"
  ).bind(listId).first();
  const position = (maxRow ? maxRow.m : -1) + 1;
  await env.DB.prepare(
    "INSERT INTO list_items (list_id, book_id, position) VALUES (?, ?, ?)"
  ).bind(listId, bookId, position).run();
  return jsonResponse({ ok: true });
}

async function handleListRemove(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const listId = validId(body.list_id);
  const bookId = validId(body.book_id);
  if (!listId || !bookId) {
    return jsonResponse({ ok: false, error: "Bad list or book id." }, 400);
  }
  await env.DB.prepare(
    "DELETE FROM list_items WHERE list_id = ? AND book_id = ?"
  ).bind(listId, bookId).run();
  return jsonResponse({ ok: true });
}

async function handleListMove(env, request) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return badBody();
  const listId = validId(body.list_id);
  const bookId = validId(body.book_id);
  if (!listId || !bookId) {
    return jsonResponse({ ok: false, error: "Bad list or book id." }, 400);
  }
  const direction = body.direction;
  if (direction !== "up" && direction !== "down") {
    return jsonResponse({ ok: false, error: "Direction must be up or down." }, 400);
  }
  const res = await env.DB.prepare(
    "SELECT book_id FROM list_items WHERE list_id = ? ORDER BY position ASC, book_id ASC"
  ).bind(listId).all();
  const items = (res.results || []).map(function (r) { return r.book_id; });
  const idx = items.indexOf(bookId);
  // Not in the list, or already at the end: nothing to move.
  if (idx === -1) return jsonResponse({ ok: true });
  const other = direction === "up" ? idx - 1 : idx + 1;
  if (other < 0 || other >= items.length) return jsonResponse({ ok: true });
  const tmp = items[idx];
  items[idx] = items[other];
  items[other] = tmp;
  // Rewrite positions from the new order, so a swap stays correct
  // even if two rows ever shared a position value.
  for (let i = 0; i < items.length; i++) {
    await env.DB.prepare(
      "UPDATE list_items SET position = ? WHERE list_id = ? AND book_id = ?"
    ).bind(i, listId, items[i]).run();
  }
  return jsonResponse({ ok: true });
}

// A simple book glyph: a filled rounded square with an open book.
const ICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect x="2" y="2" width="60" height="60" rx="14" fill="#2b1d12"/><path d="M32 20c-3.5-3-9-4-15-3v28c6-1 11.5 0 15 3c3.5-3 9-4 15-3V17c-6-1-11.5 0-15 3z" fill="#d9a441"/><path d="M32 20v28" stroke="#2b1d12" stroke-width="2"/></svg>';

const MANIFEST = {
  name: "Bookshelf",
  short_name: "Bookshelf",
  start_url: "/",
  display: "standalone",
  background_color: "#17100a",
  theme_color: "#2b1d12",
  icons: [
    { src: "/icon.svg", sizes: "any", type: "image/svg+xml" },
  ],
};

const SERVICE_WORKER = `
const CACHE = "bookshelf-v2";
const STATIC = ["/", "/manifest.json", "/icon.svg"];
self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (c) { return c.addAll(STATIC); }).then(function () { return self.skipWaiting(); })
  );
});
self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});
self.addEventListener("fetch", function (event) {
  if (event.request.method !== "GET") return;
  var url = new URL(event.request.url);
  // API calls are network-first, so the shelves are never stale.
  if (url.pathname.indexOf("/api/") === 0) {
    event.respondWith(
      fetch(event.request).catch(function () { return caches.match(event.request); })
    );
    return;
  }
  // Page visits are network-first, so a device that just unlocked
  // never gets served the gate page out of the cache. Offline, the
  // cached page is the fallback.
  if (event.request.mode === "navigate") {
    event.respondWith(
      fetch(event.request).then(function (resp) {
        if (resp && resp.ok && url.origin === self.location.origin) {
          var copy = resp.clone();
          caches.open(CACHE).then(function (c) { c.put(event.request, copy); });
        }
        return resp;
      }).catch(function () { return caches.match("/"); })
    );
    return;
  }
  // Everything else is cache-first, with new pages saved as they load.
  event.respondWith(
    caches.match(event.request).then(function (hit) {
      if (hit) return hit;
      return fetch(event.request).then(function (resp) {
        if (resp && resp.ok && url.origin === self.location.origin) {
          var copy = resp.clone();
          caches.open(CACHE).then(function (c) { c.put(event.request, copy); });
        }
        return resp;
      }).catch(function () {
        if (event.request.mode === "navigate") return caches.match("/");
        return new Response("", { status: 504 });
      });
    })
  );
});
`;

function pageHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Bookshelf</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#2b1d12">
<link rel="icon" type="image/svg+xml" href="/icon.svg">
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #17100a; color: #f2e8d5; }
  .wrap { max-width: 720px; margin: 0 auto; padding: 16px 14px 48px; }
  h1 { font-size: 28px; margin: 4px 0 10px; color: #f7ecd7; }
  h2 { font-size: 20px; margin: 0 0 10px; color: #f7ecd7; }
  h3 { font-size: 16px; margin: 16px 0 4px; color: #d9a441; }
  .titlerow { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .topbtns { display: flex; gap: 8px; }
  button { font-family: inherit; cursor: pointer; }
  .btn { padding: 9px 14px; font-size: 15px; font-weight: 600; border-radius: 8px; border: 1px solid #4a3220; background: #2b1d12; color: #f2e8d5; }
  .btn.primary { background: #d9a441; border-color: #d9a441; color: #241708; }
  .btn:disabled { opacity: .55; cursor: default; }
  .btn.small { padding: 6px 10px; font-size: 14px; }
  a.btn { display: inline-block; text-decoration: none; text-align: center; }
  .segbar { display: flex; background: #241a10; border: 1px solid #4a3220; border-radius: 10px; padding: 3px; margin: 6px 0 10px; }
  .segbtn { flex: 1; padding: 8px 4px; border: 0; border-radius: 8px; background: transparent; color: #c9b69a; font-size: 15px; font-weight: 600; }
  .segbtn.active { background: #d9a441; color: #241708; }
  input[type="search"], input[type="text"], select { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid #4a3220; background: #241a10; color: #f2e8d5; font-size: 16px; }
  input[type="search"] { margin-bottom: 10px; }
  .ctrlrow { display: flex; gap: 10px; align-items: flex-end; margin-bottom: 10px; }
  .ctrlrow label { flex: 1; display: block; font-size: 14px; color: #c9b69a; min-width: 0; }
  .ctrlrow label select { margin-top: 4px; }
  .ctrlrow .btn { flex: none; }
  .chips { display: flex; gap: 8px; margin-bottom: 10px; }
  .chip { flex: 1; padding: 8px 4px; border-radius: 999px; border: 1px solid #4a3220; background: #241a10; color: #c9b69a; font-size: 15px; font-weight: 600; }
  .chip.active { background: #d9a441; border-color: #d9a441; color: #241708; }
  .muted { color: #c9b69a; font-size: 14px; }
  p, li { line-height: 1.5; }
  .notice { padding: 10px 12px; border-radius: 8px; margin: 0 0 12px; background: #1e3a24; border: 1px solid #2f6b3a; color: #d9f2dd; font-size: 15px; }
  .notice.error { background: #3a1e1e; border-color: #6b2f2f; color: #f2d9d9; }
  #loading, #loadError { text-align: center; padding: 24px 0; color: #c9b69a; font-size: 16px; }
  .shelf { margin: 18px 0 6px; }
  .shelfhead { margin: 0; padding: 9px 12px; font-size: 17px; background: linear-gradient(#7a5230, #5a3a20); color: #f7ecd7; border-radius: 8px 8px 0 0; border: 1px solid #3a2413; border-bottom: 0; }
  .shelfhead .count { font-weight: 400; color: #e8d3ac; font-size: 14px; }
  .shelfbody { border: 1px solid #3a2413; border-top: 0; background: #20150c; padding: 8px; }
  .shelfboard { height: 10px; background: linear-gradient(#8a5f36, #5a3a20); border: 1px solid #3a2413; border-top: 0; border-radius: 0 0 6px 6px; box-shadow: 0 4px 8px rgba(0,0,0,.45); }
  .row { display: block; width: 100%; text-align: left; padding: 11px 10px; background: transparent; border: 0; border-bottom: 1px solid #33220f; color: #f2e8d5; position: relative; }
  .row:last-child { border-bottom: 0; }
  .rowtitle { display: block; font-size: 16px; font-weight: 600; padding-right: 28px; }
  .rowauthor { display: block; font-size: 14px; color: #c9b69a; padding-right: 28px; }
  .readmark { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); color: #8fce7a; font-size: 18px; font-weight: 700; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 10px; }
  .coverbox { padding: 0; border: 1px solid #3a2413; border-radius: 6px; overflow: hidden; background: #2b1d12; aspect-ratio: 2 / 3; position: relative; display: block; width: 100%; }
  .coverbox img { width: 100%; height: 100%; object-fit: cover; display: block; }
  .nocover { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px; padding: 10px; text-align: center; }
  .nctitle { font-size: 14px; font-weight: 600; color: #f2e8d5; }
  .ncauthor { font-size: 12px; color: #c9b69a; }
  .overlay { position: fixed; inset: 0; z-index: 40; display: flex; align-items: flex-start; justify-content: center; padding: 18px 12px; overflow-y: auto; }
  .overlay[hidden] { display: none; }
  #listsOverlay { z-index: 30; }
  #aboutOverlay { z-index: 35; }
  .backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.65); }
  .panel { position: relative; width: 100%; max-width: 640px; background: #241a10; border: 1px solid #4a3220; border-radius: 12px; padding: 16px; margin: auto 0; }
  .covercheck { position: absolute; top: 6px; right: 6px; width: 22px; height: 22px; border-radius: 50%; background: rgba(36, 23, 8, .88); color: #8fce7a; font-size: 14px; font-weight: 700; display: flex; align-items: center; justify-content: center; border: 1px solid #8fce7a; }
  .detailcover { width: 130px; border-radius: 8px; display: block; margin: 12px 0; }
  .detailtitle { font-size: 22px; margin: 12px 0 4px; }
  .detailauthor { font-size: 16px; color: #c9b69a; margin: 0 0 12px; }
  .detailtitlewrap { display: flex; align-items: flex-start; gap: 10px; }
  .detailtitlewrap .detailtitle { flex: 1; min-width: 0; }
  .detailtitlewrap .btn { flex: none; margin-top: 10px; }
  .editinput { width: 100%; box-sizing: border-box; margin: 6px 0; }
  .editbtns { display: flex; gap: 8px; margin: 8px 0 12px; }
  @media (min-width: 560px) {
    .detailtop { display: flex; gap: 16px; align-items: flex-start; }
    .detailcoverwrap { flex: none; }
    .detailcover { width: 150px; margin: 0; }
    .detailmain { flex: 1; min-width: 0; }
    .detailmain .detailtitle { margin-top: 0; }
    .detailmain .detailtitlewrap .btn { margin-top: 0; }
  }
  .desc { line-height: 1.5; }
  .metarow { display: flex; gap: 8px; margin: 6px 0; font-size: 15px; }
  .metalabel { color: #c9b69a; flex: none; width: 110px; }
  .detailactions { margin-top: 16px; display: flex; flex-direction: column; gap: 14px; }
  .fieldlabel { font-size: 14px; color: #c9b69a; margin-bottom: 4px; display: block; }
  .stars { position: relative; display: inline-block; font-size: 34px; line-height: 1; letter-spacing: 2px; }
  .starbg { color: #4a3220; }
  .starfg { position: absolute; left: 0; top: 0; overflow: hidden; color: #d9a441; white-space: nowrap; }
  .starbtns { position: absolute; inset: 0; display: flex; }
  .starbtns button { flex: 1; min-width: 0; background: transparent; border: 0; padding: 0; margin: 0; cursor: pointer; }
  .createrow { display: flex; gap: 8px; margin: 10px 0; }
  .createrow input { flex: 1; min-width: 0; }
  .createrow .btn { flex: none; }
  .listrow { display: flex; align-items: center; justify-content: space-between; gap: 10px; width: 100%; text-align: left; padding: 12px 10px; background: transparent; border: 0; border-bottom: 1px solid #33220f; color: #f2e8d5; font-size: 16px; font-weight: 600; }
  .listbtns { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 10px 0; }
  .listbook { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid #33220f; }
  .listthumb { width: 40px; height: 60px; object-fit: cover; border-radius: 4px; flex: none; background: #2b1d12; border: 1px solid #3a2413; }
  .listthumb.empty { display: block; }
  .listbooktitle { flex: 1; min-width: 0; text-align: left; background: transparent; border: 0; color: #f2e8d5; font-size: 16px; font-weight: 600; padding: 8px 0; }
  .picker { margin: 10px 0; }
  .pickerrow { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid #33220f; }
  .pickertitle { flex: 1; min-width: 0; font-size: 15px; font-weight: 600; }
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="titlerow">
    <h1>Bookshelf</h1>
    <div class="topbtns">
      <button type="button" class="btn" id="listsBtn">Lists</button>
      <button type="button" class="btn" id="aboutBtn">About</button>
    </div>
  </div>
  <div class="segbar" role="group" aria-label="View">
    <button type="button" class="segbtn" id="viewList">List</button>
    <button type="button" class="segbtn active" id="viewCover">Cover</button>
  </div>
  <input type="search" id="search" placeholder="Search title or author" aria-label="Search title or author">
  <div class="ctrlrow">
    <label>Sort
      <select id="sortSel">
        <option value="title">Title</option>
        <option value="author-last">Author (last name)</option>
        <option value="author-first">Author (first name)</option>
        <option value="genre">Genre</option>
        <option value="release">Release date</option>
        <option value="added">Date added</option>
      </select>
    </label>
    <button type="button" class="btn" id="dirBtn">Ascending</button>
  </div>
  <div class="chips" role="group" aria-label="Reader filter">
    <button type="button" class="chip active" data-reader="All">All</button>
    <button type="button" class="chip" data-reader="Randy">Randy</button>
    <button type="button" class="chip" data-reader="Lisa">Lisa</button>
  </div>
  <div class="ctrlrow">
    <label>Genre
      <select id="genreSel"><option value="">All genres</option></select>
    </label>
    <label>Read
      <select id="readSel">
        <option value="all">All</option>
        <option value="read">Read</option>
        <option value="unread">Unread</option>
      </select>
    </label>
  </div>
  <p id="countLine" class="muted"></p>
</header>
<main>
  <div id="notice" class="notice" hidden></div>
  <div id="loading">Loading your books...</div>
  <div id="loadError" hidden>
    <p>Could not load the books. Check your connection and try again.</p>
    <button type="button" class="btn primary" id="retryBtn">Try again</button>
  </div>
  <div id="empty" hidden><p class="muted">No books match your search or filters.</p></div>
  <div id="shelves"></div>
</main>
</div>

<div id="detailOverlay" class="overlay" hidden>
  <div class="backdrop"></div>
  <div class="panel" role="dialog" aria-modal="true" aria-label="Book details">
    <div id="detailBody"></div>
  </div>
</div>

<div id="listsOverlay" class="overlay" hidden>
  <div class="backdrop"></div>
  <div class="panel" role="dialog" aria-modal="true" aria-label="Lists">
    <div id="listsBody"></div>
  </div>
</div>

<div id="aboutOverlay" class="overlay" hidden>
  <div class="backdrop"></div>
  <div class="panel" role="dialog" aria-modal="true" aria-label="About Bookshelf">
    <button type="button" class="btn" id="aboutClose">Close</button>
    <h2>About Bookshelf</h2>
    <p>Bookshelf is the shelf for the books in the house. It shows every book that has been loaded in, with its cover, details, and a link to the file in Dropbox.</p>
    <h3>Views</h3>
    <p>Bookshelf opens on the Cover view, showing the book covers in a grid. Use the List and Cover buttons at the top to switch views. List shows each book as a row with its title and author. Cover shows the book covers in a grid. A book with no cover shows its title and author inside its box instead.</p>
    <h3>Shelves</h3>
    <p>Books are grouped into shelves. Each shelf has a heading and a count. What the shelves group by depends on the sort you pick.</p>
    <h3>Sorting</h3>
    <p>The Sort box offers Title, Author (last name), Author (first name), Genre, Release date, and Date added. Title sorting ignores a leading The. Author (last name) sorts by the last word of the author name. Genre sorting uses the first genre listed for a book, and each book sits on one shelf only. Release date uses the published date, or the year when no full date is known. Date added uses the day the book was added. The Ascending and Descending button flips the order.</p>
    <h3>Search</h3>
    <p>The search box matches words in the title or the author name. Clear it to see all books again.</p>
    <h3>Filters</h3>
    <p>The All, Randy, and Lisa buttons filter by reader. Randy shows books marked for Randy and books marked for All. Lisa shows books marked for Lisa and books marked for All. The Genre box narrows the shelves to one genre. The Read box shows all books, only books marked Read, or only books not yet read.</p>
    <h3>Book details</h3>
    <p>Tap any book to open its details: cover, description, pages, publisher, release date, genres, and the Google rating when one is known. Tap Edit beside the title to change the title or author. Saving updates the book at once, and the Dropbox file is renamed to match on the next nightly check. Tap Close to go back to the shelves.</p>
    <h3>Star ratings</h3>
    <p>In the details, tap the stars to give a book your own rating, from half a star to five stars in half star steps. Tap Clear to remove your rating. Your rating is separate from the Google rating.</p>
    <h3>Read marks and dates</h3>
    <p>The Read button in the details marks a book as read and remembers the date it was marked. A check mark means you have read the book. It shows beside read books in List view and as a small badge on the cover in Cover view. Tap the button again to clear the mark.</p>
    <h3>Reader field</h3>
    <p>The Reader box in the details says who the book is for: Randy, Lisa, or All. Change it and it saves at once.</p>
    <h3>Lists</h3>
    <p>The Lists button opens your own lists. Create a list with a name, then open it and use Add books to search the shelves and add books to it. In Edit mode you can move books up or down and remove them. Rename changes the name. Delete removes the list, not the books. A book can sit in as many lists as you like.</p>
    <h3>Dropbox links</h3>
    <p>When a book has a file in Dropbox, its details show an Open in Dropbox link. It opens the file in a new tab so you can read or download it.</p>
    <h3>Passcode</h3>
    <p>Bookshelf asks for a passcode the first time you visit on a device. Once you enter it, the device is remembered for a year, so you only enter it once per device.</p>
    <h3>Installing the app on a phone</h3>
    <p>On a phone, open Bookshelf in the browser, then use the browser menu and choose Add to Home screen or Install app. It then opens full screen like any other app, with its own icon.</p>
  </div>
</div>

<script>
var state = {
  books: [],
  lists: [],
  view: "cover",
  search: "",
  sort: "title",
  dir: "asc",
  reader: "All",
  genre: "",
  readFilter: "all",
  detailId: null
};
var listView = { selectedId: null, edit: false, picker: false, pickerQuery: "", renaming: false, confirmingDelete: false };
var noticeTimer = null;

function $(id) { return document.getElementById(id); }

function esc(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function safeCover(url) {
  if (typeof url !== "string") return "";
  var u = url.trim();
  if (/^https?:\\/\\//i.test(u)) return u;
  return "";
}

function dropboxUrl(path) {
  if (!path) return "";
  var parts = String(path).split("/").filter(function (p) { return p.length > 0; });
  if (!parts.length) return "";
  return "https://www.dropbox.com/preview/" + parts.map(function (p) { return encodeURIComponent(p); }).join("/");
}

function sortTitleOf(book) {
  var t = String(book.title || "").trim();
  return t.replace(/^the\\s+/i, "");
}

function lastNameOf(book) {
  var a = String(book.author || "").trim();
  if (!a) return "";
  var words = a.split(/\\s+/);
  return words[words.length - 1];
}

function firstGenreOf(book) {
  if (book.genres && book.genres.length) return String(book.genres[0]);
  return "";
}

function releaseKeyOf(book) {
  var d = String(book.published_date || "").trim();
  if (d) return d;
  if (book.year) return String(book.year);
  return "";
}

function yearOfKey(key) {
  var m = String(key || "").match(/^(\\d{4})/);
  return m ? m[1] : "";
}

function releaseYearOf(book) { return yearOfKey(releaseKeyOf(book)); }
function addedYearOf(book) { return yearOfKey(String(book.added_at || "")); }

function sortKeyOf(book) {
  if (state.sort === "author-last") return lastNameOf(book);
  if (state.sort === "author-first") return String(book.author || "").trim();
  if (state.sort === "genre") return firstGenreOf(book);
  if (state.sort === "release") return releaseKeyOf(book);
  if (state.sort === "added") return String(book.added_at || "").trim();
  return sortTitleOf(book);
}

function cmpText(a, b) {
  var x = a.toLowerCase(), y = b.toLowerCase();
  if (x < y) return -1;
  if (x > y) return 1;
  return 0;
}

function sortBooks(list) {
  var sorted = list.slice();
  sorted.sort(function (a, b) {
    var ka = sortKeyOf(a), kb = sortKeyOf(b);
    if (!ka && kb) return 1;
    if (ka && !kb) return -1;
    var c = cmpText(ka, kb);
    if (c) return c;
    c = cmpText(sortTitleOf(a), sortTitleOf(b));
    if (c) return c;
    c = cmpText(String(a.author || ""), String(b.author || ""));
    if (c) return c;
    return a.id - b.id;
  });
  if (state.dir === "desc") sorted.reverse();
  return sorted;
}

function groupLabelOf(book) {
  if (state.sort === "author-last" || state.sort === "author-first") {
    var a = String(book.author || "").trim();
    return a || "No author";
  }
  if (state.sort === "genre") return firstGenreOf(book) || "No genre";
  if (state.sort === "release") return releaseYearOf(book) || "No date";
  if (state.sort === "added") return addedYearOf(book) || "No date";
  var t = sortTitleOf(book);
  var ch = t ? t.charAt(0).toUpperCase() : "#";
  if (ch < "A" || ch > "Z") return "#";
  return ch;
}

function groupBooks(sorted) {
  var groups = [];
  var seen = {};
  sorted.forEach(function (book) {
    var label = groupLabelOf(book);
    if (!seen[label]) { seen[label] = []; groups.push({ label: label, books: seen[label] }); }
    seen[label].push(book);
  });
  return groups;
}

function filteredBooks() {
  var q = state.search.trim().toLowerCase();
  return state.books.filter(function (book) {
    if (q) {
      var hay = (String(book.title || "") + " " + String(book.author || "")).toLowerCase();
      if (hay.indexOf(q) === -1) return false;
    }
    if (state.reader === "Randy" && book.reader !== "Randy" && book.reader !== "All") return false;
    if (state.reader === "Lisa" && book.reader !== "Lisa" && book.reader !== "All") return false;
    if (state.genre) {
      var genres = book.genres || [];
      if (genres.indexOf(state.genre) === -1) return false;
    }
    if (state.readFilter === "read" && !book.is_read) return false;
    if (state.readFilter === "unread" && book.is_read) return false;
    return true;
  });
}

function allGenres() {
  var seen = {};
  state.books.forEach(function (book) {
    (book.genres || []).forEach(function (g) { seen[String(g)] = true; });
  });
  return Object.keys(seen).sort(function (a, b) { return cmpText(a, b); });
}

function bookById(id) {
  for (var i = 0; i < state.books.length; i++) if (state.books[i].id === id) return state.books[i];
  return null;
}

function listById(id) {
  for (var i = 0; i < state.lists.length; i++) if (state.lists[i].id === id) return state.lists[i];
  return null;
}

function showNotice(msg, isError) {
  var n = $("notice");
  n.textContent = msg;
  n.className = isError ? "notice error" : "notice";
  n.hidden = false;
  if (noticeTimer) clearTimeout(noticeTimer);
  noticeTimer = setTimeout(function () { n.hidden = true; }, 5000);
}

function postJson(path, body) {
  return fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }).then(function (resp) {
    if (resp.status === 403) { window.location.reload(); return Promise.reject(new Error("Please enter the passcode first.")); }
    return resp.json().catch(function () { return {}; }).then(function (data) {
      if (!resp.ok || !data.ok) throw new Error(data.error || "Something went wrong. Try again.");
      return data;
    });
  });
}

function refreshData() {
  return fetch("/api/list").then(function (resp) {
    if (resp.status === 403) { window.location.reload(); return null; }
    if (!resp.ok) throw new Error("Could not load the books. Try again.");
    return resp.json();
  }).then(function (data) {
    if (!data) return;
    state.books = data.books || [];
    state.lists = data.lists || [];
    if (state.genre && allGenres().indexOf(state.genre) === -1) state.genre = "";
    render();
    if (state.detailId !== null) renderDetail();
    if (!$("listsOverlay").hidden) renderLists();
  });
}

function renderGenreOptions() {
  var sel = $("genreSel");
  var current = state.genre;
  var html = '<option value="">All genres</option>';
  allGenres().forEach(function (g) {
    html += '<option value="' + esc(g) + '"' + (g === current ? " selected" : "") + ">" + esc(g) + "</option>";
  });
  sel.innerHTML = html;
}

function rowHtml(book) {
  var html = '<button type="button" class="row" data-book-id="' + book.id + '">';
  html += '<span class="rowtitle">' + esc(book.title) + "</span>";
  html += '<span class="rowauthor">' + esc(book.author || "") + "</span>";
  if (book.is_read) html += '<span class="readmark" aria-label="Read">&#10003;</span>';
  html += "</button>";
  return html;
}

function coverBoxHtml(book) {
  var cover = safeCover(book.cover_url);
  var html = '<button type="button" class="coverbox" data-book-id="' + book.id + '" aria-label="' + esc(book.title) + " by " + esc(book.author || "") + '">';
  if (cover) {
    html += '<img src="' + esc(cover) + '" alt="" loading="lazy">';
  } else {
    html += '<span class="nocover"><span class="nctitle">' + esc(book.title) + '</span><span class="ncauthor">' + esc(book.author || "") + "</span></span>";
  }
  if (book.is_read) html += '<span class="covercheck" aria-label="Read">&#10003;</span>';
  html += "</button>";
  return html;
}

function render() {
  renderGenreOptions();
  var filtered = filteredBooks();
  var sorted = sortBooks(filtered);
  var groups = groupBooks(sorted);
  var total = state.books.length;
  if (filtered.length === total) {
    $("countLine").textContent = total === 1 ? "1 book." : total + " books.";
  } else {
    $("countLine").textContent = "Showing " + filtered.length + " of " + total + " books.";
  }
  $("empty").hidden = filtered.length !== 0;
  var html = "";
  groups.forEach(function (group) {
    html += '<section class="shelf"><h2 class="shelfhead">' + esc(group.label) + ' <span class="count">(' + group.books.length + ")</span></h2>";
    html += '<div class="shelfbody">';
    if (state.view === "cover") {
      html += '<div class="grid">';
      group.books.forEach(function (book) { html += coverBoxHtml(book); });
      html += "</div>";
    } else {
      group.books.forEach(function (book) { html += rowHtml(book); });
    }
    html += "</div>";
    html += '<div class="shelfboard"></div></section>';
  });
  $("shelves").innerHTML = html;
}

// ---- Detail overlay ----

function formatRating(r) {
  if (r === null || r === undefined) return "";
  return (r % 1 === 0) ? String(r) : r.toFixed(1);
}

function metaRow(label, value) {
  return '<div class="metarow"><span class="metalabel">' + esc(label) + '</span><span>' + esc(value) + "</span></div>";
}

function starStepsHtml(rating) {
  var pct = rating ? (rating / 5 * 100) : 0;
  var html = '<div class="stars" role="group" aria-label="Your star rating">';
  html += '<span class="starbg" aria-hidden="true">&#9733;&#9733;&#9733;&#9733;&#9733;</span>';
  html += '<span class="starfg" style="width: ' + pct + '%" aria-hidden="true">&#9733;&#9733;&#9733;&#9733;&#9733;</span>';
  html += '<span class="starbtns">';
  for (var i = 1; i <= 10; i++) {
    var v = (i / 2).toFixed(1);
    html += '<button type="button" data-action="set-rating" data-rating="' + v + '" aria-label="' + v + ' stars"></button>';
  }
  html += "</span></div>";
  return html;
}

function openDetail(id) {
  state.detailId = id;
  detailEditing = false;
  renderDetail();
  $("detailOverlay").hidden = false;
}

function closeDetail() {
  state.detailId = null;
  detailEditing = false;
  $("detailOverlay").hidden = true;
}

var detailEditing = false;

function renderDetail() {
  var book = bookById(state.detailId);
  if (!book) { closeDetail(); return; }
  var html = "";
  html += '<button type="button" class="btn" data-action="close-detail">Close</button>';
  html += '<div class="detailtop">';
  var cover = safeCover(book.cover_url);
  html += '<div class="detailcoverwrap">';
  if (cover) html += '<img class="detailcover" src="' + esc(cover) + '" alt="">';
  html += "</div>";
  html += '<div class="detailmain">';
  if (detailEditing) {
    html += '<label class="fieldlabel" for="editTitle">Title</label>';
    html += '<input type="text" class="editinput" id="editTitle" maxlength="200" value="' + esc(book.title) + '">';
    html += '<label class="fieldlabel" for="editAuthor">Author</label>';
    html += '<input type="text" class="editinput" id="editAuthor" maxlength="120" value="' + esc(book.author || "") + '">';
    html += '<div class="editbtns"><button type="button" class="btn primary" data-action="save-title-author">Save</button>';
    html += '<button type="button" class="btn" data-action="cancel-title-author">Cancel</button></div>';
  } else {
    html += '<div class="detailtitlewrap"><h2 class="detailtitle">' + esc(book.title) + "</h2>";
    html += '<button type="button" class="btn small" data-action="edit-title-author">Edit</button></div>';
    html += '<p class="detailauthor">' + esc(book.author || "") + "</p>";
  }
  if (book.description) html += '<p class="desc">' + esc(book.description) + "</p>";
  if (book.page_count) html += metaRow("Pages", String(book.page_count));
  if (book.publisher) html += metaRow("Publisher", book.publisher);
  var rel = String(book.published_date || "").trim() || (book.year ? String(book.year) : "");
  if (rel) html += metaRow("Release date", rel);
  if (book.genres && book.genres.length) html += metaRow("Genres", book.genres.join(", "));
  if (book.google_rating !== null && book.google_rating !== undefined) {
    var g = formatRating(book.google_rating);
    if (book.ratings_count) g += " (" + Number(book.ratings_count).toLocaleString("en-US") + " ratings)";
    html += metaRow("Google rating", g);
  }
  html += '<div class="detailactions">';
  html += '<div><span class="fieldlabel">Your star rating</span>' + starStepsHtml(book.rating);
  html += '<p class="muted">' + ((book.rating === null || book.rating === undefined) ? "Not rated yet." : "Your rating: " + formatRating(book.rating) + " out of 5.") + "</p>";
  html += '<button type="button" class="btn small" data-action="clear-rating"' + ((book.rating === null || book.rating === undefined) ? " disabled" : "") + ">Clear</button></div>";
  var readLabel = book.is_read ? ("Read" + (book.read_on ? " on " + book.read_on : "")) : "Mark as read";
  html += '<div><button type="button" class="btn' + (book.is_read ? " primary" : "") + '" data-action="toggle-read" aria-pressed="' + (book.is_read ? "true" : "false") + '">' + esc(readLabel) + "</button></div>";
  html += '<div><label class="fieldlabel" for="detailReader">Reader</label><select id="detailReader">';
  ["Randy", "Lisa", "All"].forEach(function (r) {
    html += '<option value="' + r + '"' + (book.reader === r ? " selected" : "") + ">" + r + "</option>";
  });
  html += "</select></div>";
  html += '<div><span class="fieldlabel">Add to list</span>';
  if (state.lists.length) {
    html += '<select id="detailListSel" aria-label="Choose a list">';
    state.lists.forEach(function (l) { html += '<option value="' + l.id + '">' + esc(l.name) + "</option>"; });
    html += "</select>";
    html += '<button type="button" class="btn" data-action="add-to-list">Add</button>';
  } else {
    html += '<select disabled aria-label="Choose a list"><option>No lists yet</option></select>';
    html += '<button type="button" class="btn" disabled>Add</button>';
    html += '<p class="muted">No lists yet. Create one from the Lists view first.</p>';
  }
  html += "</div>";
  var db = dropboxUrl(book.dropbox_path);
  if (db) html += '<div><a class="btn" href="' + esc(db) + '" target="_blank" rel="noopener noreferrer">Open in Dropbox</a></div>';
  html += "</div>";
  html += "</div>";
  html += "</div>";
  $("detailBody").innerHTML = html;
}

function saveTitleAuthor(book) {
  var titleEl = $("editTitle");
  var authorEl = $("editAuthor");
  if (!titleEl || !authorEl) return;
  postJson("/api/set-title-author", { id: book.id, title: titleEl.value, author: authorEl.value }).then(function (data) {
    detailEditing = false;
    return refreshData().then(function () { return data; });
  }).then(function (data) {
    showNotice(data && data.new_filename ? "Saved. The Dropbox file will be renamed to " + data.new_filename + "." : "Saved.");
  }).catch(function (err) {
    showNotice(err.message, true);
  });
}

function saveRating(book, rating) {
  postJson("/api/set-rating", { id: book.id, rating: rating }).then(function () {
    return refreshData();
  }).then(function () {
    showNotice(rating === null ? "Rating cleared." : "Rating saved.");
  }).catch(function (err) { showNotice(err.message, true); });
}

function saveRead(book, read) {
  postJson("/api/set-read", { id: book.id, read: read }).then(function () {
    return refreshData();
  }).then(function () {
    showNotice(read ? "Marked as read." : "Read mark removed.");
  }).catch(function (err) { showNotice(err.message, true); });
}

function saveReader(book, reader) {
  postJson("/api/set-reader", { id: book.id, reader: reader }).then(function () {
    return refreshData();
  }).then(function () {
    showNotice("Reader saved.");
  }).catch(function (err) {
    showNotice(err.message, true);
    renderDetail();
  });
}

function addDetailToList(book) {
  var sel = $("detailListSel");
  if (!sel) return;
  var list = listById(Number(sel.value));
  if (!list) return;
  postJson("/api/lists/add", { list_id: list.id, book_id: book.id })
    .then(function (data) { return refreshData().then(function () { return data; }); })
    .then(function (data) { showNotice(data && data.already ? "That book is already in " + list.name + "." : "Book added to " + list.name + "."); })
    .catch(function (err) { showNotice(err.message, true); });
}

// ---- Lists view ----

function openLists() {
  listView.selectedId = null;
  listView.edit = false;
  listView.picker = false;
  listView.renaming = false;
  listView.confirmingDelete = false;
  renderLists();
  $("listsOverlay").hidden = false;
}

function closeLists() { $("listsOverlay").hidden = true; }

function renderLists() {
  var list = listView.selectedId !== null ? listById(listView.selectedId) : null;
  if (listView.selectedId !== null && !list) {
    listView.selectedId = null;
    listView.edit = false;
    listView.picker = false;
    list = null;
  }
  var html = "";
  html += '<button type="button" class="btn" data-action="close-lists">Close</button>';
  if (!list) {
    html += "<h2>Lists</h2>";
    html += '<div class="createrow"><input type="text" id="newListName" placeholder="New list name" maxlength="60" aria-label="New list name"><button type="button" class="btn primary" data-action="create-list">Create list</button></div>';
    if (!state.lists.length) html += '<p class="muted">No lists yet. Create one to group books your own way.</p>';
    state.lists.forEach(function (l) {
      html += '<button type="button" class="listrow" data-action="open-list" data-list-id="' + l.id + '"><span>' + esc(l.name) + '</span><span class="muted">' + l.items.length + (l.items.length === 1 ? " book" : " books") + "</span></button>";
    });
  } else {
    html += '<button type="button" class="btn small" data-action="back-lists">All lists</button>';
    if (listView.renaming) {
      html += '<div class="createrow"><input type="text" id="renameInput" value="' + esc(list.name) + '" maxlength="60" aria-label="List name"><button type="button" class="btn primary" data-action="save-rename">Save</button><button type="button" class="btn" data-action="cancel-rename">Cancel</button></div>';
    } else {
      html += "<h2>" + esc(list.name) + "</h2>";
      html += '<div class="listbtns"><button type="button" class="btn small" data-action="start-rename">Rename</button>';
      if (listView.confirmingDelete) {
        html += '<span class="muted">Delete this list? The books stay on your shelves.</span><button type="button" class="btn small" data-action="confirm-delete">Delete</button><button type="button" class="btn" data-action="cancel-delete">Cancel</button>';
      } else {
        html += '<button type="button" class="btn small" data-action="start-delete">Delete list</button>';
      }
      html += "</div>";
    }
    html += '<div class="listbtns"><button type="button" class="btn small" data-action="toggle-edit">' + (listView.edit ? "Done" : "Edit") + '</button><button type="button" class="btn small" data-action="toggle-picker">' + (listView.picker ? "Hide picker" : "Add books") + "</button></div>";
    if (listView.picker) {
      html += '<div class="picker"><input type="search" id="pickerSearch" placeholder="Search title or author" value="' + esc(listView.pickerQuery) + '" aria-label="Search books to add"><div id="pickerResults"></div></div>';
    }
    if (!list.items.length) html += '<p class="muted">No books in this list yet.</p>';
    list.items.forEach(function (bookId, idx) {
      var book = bookById(bookId);
      if (!book) return;
      var cover = safeCover(book.cover_url);
      html += '<div class="listbook">';
      if (cover) html += '<img class="listthumb" src="' + esc(cover) + '" alt="" loading="lazy">';
      else html += '<span class="listthumb empty" aria-hidden="true"></span>';
      html += '<button type="button" class="listbooktitle" data-action="open-book" data-book-id="' + book.id + '">' + esc(book.title) + "</button>";
      if (listView.edit) {
        html += '<button type="button" class="btn small" data-action="move-up" data-book-id="' + book.id + '"' + (idx === 0 ? " disabled" : "") + ">Up</button>";
        html += '<button type="button" class="btn small" data-action="move-down" data-book-id="' + book.id + '"' + (idx === list.items.length - 1 ? " disabled" : "") + ">Down</button>";
        html += '<button type="button" class="btn small" data-action="remove-from-list" data-book-id="' + book.id + '">Remove</button>';
      }
      html += "</div>";
    });
  }
  $("listsBody").innerHTML = html;
  if (list && listView.picker) renderPickerResults();
}

function renderPickerResults() {
  var list = listById(listView.selectedId);
  var box = $("pickerResults");
  if (!list || !box) return;
  var q = listView.pickerQuery.trim().toLowerCase();
  var inList = {};
  list.items.forEach(function (id) { inList[id] = true; });
  var matches = state.books.filter(function (book) {
    if (inList[book.id]) return false;
    if (!q) return true;
    var hay = (String(book.title || "") + " " + String(book.author || "")).toLowerCase();
    return hay.indexOf(q) !== -1;
  });
  var sorted = sortBooks(matches);
  var shown = sorted.slice(0, 50);
  var html = "";
  shown.forEach(function (book) {
    html += '<div class="pickerrow"><span class="pickertitle">' + esc(book.title) + '</span><span class="muted">' + esc(book.author || "") + '</span><button type="button" class="btn small" data-action="picker-add" data-book-id="' + book.id + '">Add</button></div>';
  });
  if (!shown.length) html += '<p class="muted">No matching books to add.</p>';
  if (sorted.length > 50) html += '<p class="muted">Showing 50 of ' + sorted.length + ' matches. Narrow your search to see more.</p>';
  box.innerHTML = html;
}

function createList() {
  var input = $("newListName");
  var name = input ? input.value.trim() : "";
  if (!name) { showNotice("Give the list a name first.", true); return; }
  postJson("/api/lists/create", { name: name }).then(function () {
    return refreshData();
  }).then(function () { showNotice("List created."); })
  .catch(function (err) { showNotice(err.message, true); });
}

function saveRename(list) {
  var input = $("renameInput");
  var name = input ? input.value.trim() : "";
  if (!name) { showNotice("Give the list a name first.", true); return; }
  postJson("/api/lists/rename", { id: list.id, name: name }).then(function () {
    listView.renaming = false;
    return refreshData();
  }).then(function () { showNotice("List renamed."); })
  .catch(function (err) { showNotice(err.message, true); });
}

function deleteList(list) {
  postJson("/api/lists/delete", { id: list.id }).then(function () {
    listView.selectedId = null;
    listView.edit = false;
    listView.picker = false;
    listView.renaming = false;
    listView.confirmingDelete = false;
    return refreshData();
  }).then(function () { showNotice("List deleted."); })
  .catch(function (err) { showNotice(err.message, true); });
}

function moveInList(list, bookId, direction) {
  postJson("/api/lists/move", { list_id: list.id, book_id: bookId, direction: direction })
    .then(function () { return refreshData(); })
    .catch(function (err) { showNotice(err.message, true); });
}

function removeFromList(list, bookId) {
  postJson("/api/lists/remove", { list_id: list.id, book_id: bookId })
    .then(function () { return refreshData(); })
    .then(function () { showNotice("Book removed from the list."); })
    .catch(function (err) { showNotice(err.message, true); });
}

function addToList(list, bookId) {
  postJson("/api/lists/add", { list_id: list.id, book_id: bookId })
    .then(function (data) { return refreshData().then(function () { return data; }); })
    .then(function (data) { showNotice(data && data.already ? "That book is already in the list." : "Book added to the list."); })
    .catch(function (err) { showNotice(err.message, true); });
}

// ---- Wiring ----

$("viewList").addEventListener("click", function () { setView("list"); });
$("viewCover").addEventListener("click", function () { setView("cover"); });

function setView(v) {
  state.view = v;
  $("viewList").classList.toggle("active", v === "list");
  $("viewCover").classList.toggle("active", v === "cover");
  render();
}

$("search").addEventListener("input", function (e) { state.search = e.target.value; render(); });
$("sortSel").addEventListener("change", function (e) { state.sort = e.target.value; render(); });
$("dirBtn").addEventListener("click", function () {
  state.dir = state.dir === "asc" ? "desc" : "asc";
  $("dirBtn").textContent = state.dir === "asc" ? "Ascending" : "Descending";
  render();
});
document.querySelectorAll(".chip").forEach(function (chip) {
  chip.addEventListener("click", function () {
    state.reader = chip.getAttribute("data-reader");
    document.querySelectorAll(".chip").forEach(function (c) { c.classList.toggle("active", c === chip); });
    render();
  });
});
$("genreSel").addEventListener("change", function (e) { state.genre = e.target.value; render(); });
$("readSel").addEventListener("change", function (e) { state.readFilter = e.target.value; render(); });

$("shelves").addEventListener("click", function (e) {
  var t = e.target.closest("[data-book-id]");
  if (t) openDetail(Number(t.getAttribute("data-book-id")));
});

$("detailBody").addEventListener("click", function (e) {
  var t = e.target.closest("[data-action]");
  if (!t) return;
  var action = t.getAttribute("data-action");
  var book = bookById(state.detailId);
  if (!book) return;
  if (action === "close-detail") closeDetail();
  else if (action === "set-rating") saveRating(book, parseFloat(t.getAttribute("data-rating")));
  else if (action === "clear-rating") saveRating(book, null);
  else if (action === "toggle-read") saveRead(book, !book.is_read);
  else if (action === "add-to-list") addDetailToList(book);
  else if (action === "edit-title-author") {
    detailEditing = true;
    renderDetail();
    var inp = $("editTitle");
    if (inp) { inp.focus(); inp.select(); }
  }
  else if (action === "save-title-author") saveTitleAuthor(book);
  else if (action === "cancel-title-author") { detailEditing = false; renderDetail(); }
});

$("detailBody").addEventListener("keydown", function (e) {
  if (e.key === "Enter" && (e.target.id === "editTitle" || e.target.id === "editAuthor")) {
    e.preventDefault();
    var book = bookById(state.detailId);
    if (book) saveTitleAuthor(book);
  }
});

$("detailBody").addEventListener("change", function (e) {
  if (e.target.id === "detailReader") {
    var book = bookById(state.detailId);
    if (book) saveReader(book, e.target.value);
  }
});

$("listsBtn").addEventListener("click", openLists);
$("aboutBtn").addEventListener("click", function () { $("aboutOverlay").hidden = false; });
$("aboutClose").addEventListener("click", function () { $("aboutOverlay").hidden = true; });

$("listsBody").addEventListener("click", function (e) {
  var t = e.target.closest("[data-action]");
  if (!t) return;
  var action = t.getAttribute("data-action");
  if (action === "close-lists") { closeLists(); return; }
  if (action === "back-lists") {
    listView.selectedId = null; listView.edit = false; listView.picker = false;
    listView.renaming = false; listView.confirmingDelete = false; renderLists(); return;
  }
  if (action === "create-list") { createList(); return; }
  if (action === "open-list") {
    listView.selectedId = Number(t.getAttribute("data-list-id"));
    listView.edit = false; listView.picker = false;
    listView.renaming = false; listView.confirmingDelete = false;
    renderLists(); return;
  }
  if (action === "open-book") { openDetail(Number(t.getAttribute("data-book-id"))); return; }
  var list = listById(listView.selectedId);
  if (!list) return;
  if (action === "toggle-edit") { listView.edit = !listView.edit; renderLists(); }
  else if (action === "toggle-picker") {
    listView.picker = !listView.picker; renderLists();
    if (listView.picker) { var s = $("pickerSearch"); if (s) s.focus(); }
  }
  else if (action === "start-rename") {
    listView.renaming = true; renderLists();
    var inp = $("renameInput"); if (inp) { inp.focus(); inp.select(); }
  }
  else if (action === "cancel-rename") { listView.renaming = false; renderLists(); }
  else if (action === "save-rename") { saveRename(list); }
  else if (action === "start-delete") { listView.confirmingDelete = true; renderLists(); }
  else if (action === "cancel-delete") { listView.confirmingDelete = false; renderLists(); }
  else if (action === "confirm-delete") { deleteList(list); }
  else if (action === "move-up") { moveInList(list, Number(t.getAttribute("data-book-id")), "up"); }
  else if (action === "move-down") { moveInList(list, Number(t.getAttribute("data-book-id")), "down"); }
  else if (action === "remove-from-list") { removeFromList(list, Number(t.getAttribute("data-book-id"))); }
  else if (action === "picker-add") { addToList(list, Number(t.getAttribute("data-book-id"))); }
});

$("listsBody").addEventListener("input", function (e) {
  if (e.target.id === "pickerSearch") { listView.pickerQuery = e.target.value; renderPickerResults(); }
});

$("listsBody").addEventListener("keydown", function (e) {
  if (e.key === "Enter" && e.target.id === "newListName") { e.preventDefault(); createList(); }
  if (e.key === "Enter" && e.target.id === "renameInput") {
    e.preventDefault();
    var list = listById(listView.selectedId);
    if (list) saveRename(list);
  }
});

document.querySelectorAll(".backdrop").forEach(function (b) {
  b.addEventListener("click", function () {
    if (b.parentElement.id === "detailOverlay") closeDetail();
    else if (b.parentElement.id === "listsOverlay") closeLists();
    else if (b.parentElement.id === "aboutOverlay") $("aboutOverlay").hidden = true;
  });
});

document.addEventListener("keydown", function (e) {
  if (e.key !== "Escape") return;
  if (!$("detailOverlay").hidden) closeDetail();
  else if (!$("listsOverlay").hidden) closeLists();
  else if (!$("aboutOverlay").hidden) $("aboutOverlay").hidden = true;
});

function loadList() {
  $("loading").hidden = false;
  $("loadError").hidden = true;
  fetch("/api/list").then(function (resp) {
    if (resp.status === 403) { window.location.reload(); return null; }
    if (!resp.ok) throw new Error("Could not load the books. Try again.");
    return resp.json();
  }).then(function (data) {
    if (!data) return;
    state.books = data.books || [];
    state.lists = data.lists || [];
    $("loading").hidden = true;
    render();
  }).catch(function () {
    $("loading").hidden = true;
    $("loadError").hidden = false;
  });
}

$("retryBtn").addEventListener("click", loadList);

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").catch(function () {});
}

loadList();
</script>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      // Passcode gate: once SITE_PASSCODE is set, everything except
      // the unlock endpoint and the installable-app files needs a
      // device token. A browser visit gets the code box; an API call
      // gets a 403 so the app can send the browser back to the box.
      const gateExempt =
        path === "/api/unlock" ||
        path === "/sw.js" ||
        path === "/manifest.json" ||
        path === "/icon.svg" ||
        path === "/favicon.ico";
      if (!gateExempt && !(await gateUnlocked(env, request))) {
        if (path === "/" && request.method === "GET") {
          return new Response(gateHtml(), {
            headers: {
              "Content-Type": "text/html; charset=utf-8",
              "Cache-Control": "no-store",
              "X-Robots-Tag": "noindex, nofollow",
            },
          });
        }
        return jsonResponse({ ok: false, error: "Please enter the passcode first." }, 403);
      }
      if (path === "/api/unlock" && request.method === "POST") {
        return await handleUnlock(env, request);
      }
      if (path === "/" && request.method === "GET") {
        return new Response(pageHtml(), {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex, nofollow",
          },
        });
      }
      if (path === "/api/list" && request.method === "GET") {
        return await handleList(env);
      }
      if (path === "/api/set-read" && request.method === "POST") {
        return await handleSetRead(env, request);
      }
      if (path === "/api/set-rating" && request.method === "POST") {
        return await handleSetRating(env, request);
      }
      if (path === "/api/set-reader" && request.method === "POST") {
        return await handleSetReader(env, request);
      }
      if (path === "/api/set-title-author" && request.method === "POST") {
        return await handleSetTitleAuthor(env, request);
      }
      if (path === "/api/lists/create" && request.method === "POST") {
        return await handleListCreate(env, request);
      }
      if (path === "/api/lists/rename" && request.method === "POST") {
        return await handleListRename(env, request);
      }
      if (path === "/api/lists/delete" && request.method === "POST") {
        return await handleListDelete(env, request);
      }
      if (path === "/api/lists/add" && request.method === "POST") {
        return await handleListAdd(env, request);
      }
      if (path === "/api/lists/remove" && request.method === "POST") {
        return await handleListRemove(env, request);
      }
      if (path === "/api/lists/move" && request.method === "POST") {
        return await handleListMove(env, request);
      }
      if (path === "/manifest.json") {
        return new Response(JSON.stringify(MANIFEST), {
          headers: { "Content-Type": "application/manifest+json", "X-Robots-Tag": "noindex, nofollow" },
        });
      }
      if (path === "/sw.js") {
        return new Response(SERVICE_WORKER, {
          headers: { "Content-Type": "application/javascript", "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow" },
        });
      }
      if (path === "/icon.svg" || path === "/favicon.ico") {
        return new Response(ICON_SVG, {
          headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" },
        });
      }
      if (path.indexOf("/api/") === 0) {
        return jsonResponse({ ok: false, error: "Not found." }, 404);
      }
      return new Response("Not found", { status: 404 });
    } catch (err) {
      if (path.indexOf("/api/") === 0) {
        return jsonResponse({ ok: false, error: "Something went wrong on the server." }, 500);
      }
      return new Response("Something went wrong.", { status: 500 });
    }
  },
};

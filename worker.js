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
    row.enriched = row.enriched || "";
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
const CACHE = "bookshelf-v13";
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
  input[type="search"], input[type="text"], select { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid #4a3220; background: #241a10; color: #f2e8d5; font-size: 16px; }
  input[type="search"] { margin-bottom: 10px; }
  .searchrow { display: flex; gap: 8px; margin-bottom: 10px; }
  .searchrow input[type="search"] { flex: 1; min-width: 0; margin-bottom: 0; }
  .searchrow .btn { flex: none; }
  .filterspanel { border: 1px solid #4a3220; border-radius: 10px; background: #241a10; padding: 12px; margin-bottom: 10px; }
  .filterspanel[hidden] { display: none; }
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
  .jumpto { display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 12px; }
  .jumpbtn { min-width: 28px; padding: 5px 6px; border-radius: 6px; border: 1px solid #4a3220; background: #241a10; color: #f2e8d5; font-size: 14px; font-weight: 600; }
  .jumpbtn:disabled { opacity: .35; cursor: default; }
  .topbtn { position: fixed; right: 14px; bottom: 16px; z-index: 20; padding: 10px 14px; border-radius: 999px; border: 1px solid #d9a441; background: #d9a441; color: #241708; font-size: 15px; font-weight: 700; box-shadow: 0 4px 12px rgba(0,0,0,.5); }
  .topbtn[hidden] { display: none; }
  .btn.active { background: #d9a441; border-color: #d9a441; color: #241708; }
  .viewrow { display: flex; gap: 8px; margin-bottom: 10px; }
  .spineshelf { margin: 18px 0 6px; }
  .plaque { display: block; width: fit-content; margin: 0 auto 8px; padding: 5px 18px; font-size: 15px; font-weight: 700; color: #3a2413; background: linear-gradient(#e8c96a, #c9a13a); border: 1px solid #8a6d1f; border-radius: 4px; box-shadow: 0 2px 5px rgba(0,0,0,.5); text-align: center; }
  .spinebody { border: 1px solid #3a2413; background: #20150c; padding: 10px 0 0; overflow: hidden; }
  .spinerow { display: flex; gap: 2px; align-items: flex-end; }
  .spine { position: relative; width: 36px; flex: none; border: 1px solid rgba(0,0,0,.45); border-radius: 3px 3px 0 0; padding: 3px 0; overflow: hidden; }
  .spinetext { writing-mode: vertical-rl; text-orientation: mixed; display: block; height: 100%; overflow: hidden; }
  .spinetitle { display: block; font-size: 13px; font-weight: 700; color: #f7ecd7; white-space: nowrap; margin-left: 3px; }
  .spineauthor { display: block; font-size: 11px; color: #e8d3ac; white-space: nowrap; }
  .spinecheck { position: absolute; bottom: 4px; left: 50%; transform: translateX(-50%); width: 16px; height: 16px; border-radius: 50%; background: rgba(36, 23, 8, .9); color: #8fce7a; font-size: 11px; font-weight: 700; display: flex; align-items: center; justify-content: center; border: 1px solid #8fce7a; }
  .flipoverlay { position: fixed; inset: 0; z-index: 38; display: flex; align-items: center; justify-content: center; background: rgba(0,0,0,.5); }
  .flipoverlay[hidden] { display: none; }
  .flipstage { perspective: 1200px; }
  .flipcard { width: 210px; height: 315px; position: relative; transform-style: preserve-3d; transition: transform .55s ease; transform: translateY(60px) scale(.8) rotateY(180deg); }
  .flipcard.open { transform: translateY(0) scale(1) rotateY(0deg); }
  .flipface { position: absolute; inset: 0; backface-visibility: hidden; -webkit-backface-visibility: hidden; border-radius: 6px; overflow: hidden; }
  .flipfront { padding: 0; border: 1px solid #3a2413; background: #2b1d12; display: block; width: 100%; height: 100%; }
  .flipfront img { width: 100%; height: 100%; object-fit: cover; display: block; }
  .flipback { transform: rotateY(180deg); border: 1px solid rgba(0,0,0,.45); display: flex; }
  .flipback .spinetext { padding: 10px 0; }
  .flipback .spinetitle { font-size: 19px; }
  .flipback .spineauthor { font-size: 15px; }
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
  .detailcover { width: 110px; border-radius: 8px; display: block; margin: 0; }
  .detailtitle { font-size: 22px; margin: 12px 0 4px; }
  .detailauthor { font-size: 16px; color: #c9b69a; margin: 0 0 12px; }
  .detailtitlewrap { display: flex; align-items: flex-start; gap: 10px; }
  .detailtitlewrap .detailtitle { flex: 1; min-width: 0; }
  .detailtitlewrap .btn { flex: none; margin-top: 10px; }
  .editinput { width: 100%; box-sizing: border-box; margin: 6px 0; }
  .editbtns { display: flex; gap: 8px; margin: 8px 0 12px; }
  .detailtop { display: flex; gap: 12px; align-items: flex-start; }
  .detailcoverwrap { flex: none; }
  .detailmain { flex: 1; min-width: 0; }
  .detailsection { overflow: hidden; }
  .detailunder { }
  .detailmain .detailtitle { margin-top: 0; }
  .detailmain .detailtitlewrap .btn { margin-top: 0; }
  .detailmain .stars { font-size: 28px; }
  .ratingrow { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .ratingrow .stars { flex: none; }
  .ratingrow .btn { flex: none; }
  @media (min-width: 560px) {
    .detailtop { gap: 16px; }
    .detailcover { width: 150px; }
    .detailmain .stars { font-size: 34px; }
  }
  .desc { line-height: 1.5; }
  .detailtop + .desc { margin-top: 14px; }
  .detailunder + .desc { margin-top: 14px; }
  .inlinerow { display: flex; align-items: center; gap: 8px; }
  .fieldlabel.inline { margin-bottom: 0; flex: none; }
  select.narrowselect { width: auto; min-width: 110px; flex: none; }
  .linkrow { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
  .srclink { color: #d9a441; font-size: 15px; }
  .metarow { display: block; margin: 8px 0; font-size: 15px; }
  .metalabel { display: block; color: #c9b69a; font-size: 13px; margin-bottom: 1px; }
  @media (min-width: 560px) {
    .metarow { display: flex; gap: 8px; margin: 6px 0; }
    .metalabel { flex: none; width: 110px; font-size: 15px; margin-bottom: 0; }
  }
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
  <div class="viewrow">
    <button type="button" class="btn active" id="spineView">Spine</button>
    <button type="button" class="btn" id="coverView">Cover</button>
  </div>
  <div class="searchrow">
    <input type="search" id="search" placeholder="Search title or author" aria-label="Search title or author">
    <button type="button" class="btn" id="filtersBtn" aria-expanded="false">Filters</button>
  </div>
  <div id="filtersPanel" class="filterspanel" hidden>
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
    <button type="button" class="btn" id="filtersClose">Close</button>
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
  <div id="jumpto" class="jumpto" role="group" aria-label="Jump to"></div>
  <div id="shelves"></div>
</main>
</div>

<button type="button" id="topBtn" class="topbtn" hidden>Back to top</button>

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
    <p>Bookshelf has two views, Spine and Cover. It opens on Spine view. Use the Spine and Cover buttons under Lists and About to switch. Bookshelf shows the book covers in a grid in Cover view. A book with no cover shows its title and author inside its box instead. Tap any cover to open the book.</p>
    <h3>Shelves</h3>
    <p>Books are grouped into shelves. Each shelf has a heading and a count. What the shelves group by depends on the sort you pick. Sorting by author groups books by the first letter of the author name, the same as sorting by title groups by the first letter of the title. In Spine view the shelves are packed with spines instead, and each shelf has a plaque showing the range of books on it.</p>
    <h3>Spine view</h3>
    <p>Spine view shows the books as shelves of spines, like books on a real shelf. Each spine shows the title and author on two lines. Each shelf is packed full, with the spines sharing its width exactly so no space is left at the end. A brass plaque in the middle at the top of the shelf shows the first and last books on it, for example A to Bi. The range follows the sort you picked. Tap a spine and the book slides out of the shelf and turns around to show its cover. Tap the cover to open the book's details. Tap anywhere else to put the book back on the shelf.</p>
    <h3>Sorting</h3>
    <p>The Sort box in the Filters popup offers Title, Author (last name), Author (first name), Genre, Release date, and Date added. Title sorting ignores a leading The. Author (last name) sorts by the last word of the author name. Genre sorting uses the first genre listed for a book, and each book sits on one shelf only. Release date uses the published date, or the year when no full date is known. Date added uses the day the book was added. The Ascending and Descending button flips the order.</p>
    <h3>Search</h3>
    <p>The search box matches words in the title or the author name. Clear it to see all books again.</p>
    <h3>Filters</h3>
    <p>The search box stays on the page. Tap Filters to open the rest of the controls: Sort, Ascending and Descending, the All, Randy, and Lisa reader buttons, the Genre box, and the Read box. Tap Filters again, tap Close, or tap outside the box to close it. Randy shows books marked for Randy and books marked for All. Lisa shows books marked for Lisa and books marked for All. The Genre box lists 28 genres. Picking one narrows the shelves to books in that genre and its subgenres, so Fiction includes Historical Fiction, Classics, and Magical Realism. The Read box shows all books, only books marked Read, or only books not yet read.</p>
    <h3>Jump to and back to top</h3>
    <p>The jump-to row under the search box has the letters A to Z and a hash for the rest. Tap a letter to jump to the books starting with that letter. It works in both views. When you have scrolled down the page, a Back to top button appears at the bottom right. Tap it to go back to the top.</p>
    <h3>Book details</h3>
    <p>Tap any book to open its details. The cover sits on the left, with the title, your rating with the Read button beside the stars, the Google rating with its number of ratings in brackets when one is known, release date, pages, genres, and publisher beside it, in that order, while they fit. A section that would run past the bottom of the cover moves under the cover whole, with the sections after it, so a label and its value never split apart. The description comes right after the last field, under the cover. Then come the Reader dropdown, the List dropdown with its + button, and the Dropbox and source links. Tap Edit beside the title to change the title or author. Saving updates the book at once, and the Dropbox file is renamed to match on the next nightly check. Tap Close to go back to the shelves.</p>
    <h3>Star ratings</h3>
    <p>In the details, tap the stars to give a book your own rating, from half a star to five stars in half star steps. Tap the first half star again to remove your rating. Your rating is separate from the Google rating.</p>
    <h3>Read marks and dates</h3>
    <p>The Read button in the details marks a book as read and remembers the date it was marked. A check mark means you have read the book. It shows as a small badge on the cover, and as a small check on the spine in Spine view. Tap the button again to clear the mark.</p>
    <h3>Reader field</h3>
    <p>The Reader dropdown in the details says who the book is for: Randy, Lisa, or All. It sits beside the word Reader. Change it and it saves at once.</p>
    <h3>Lists</h3>
    <p>The Lists button opens your own lists. Create a list with a name, then open it and use Add books to search the shelves and add books to it. In Edit mode you can move books up or down and remove them. Rename changes the name. Delete removes the list, not the books. A book can sit in as many lists as you like. In a book's details, pick a list from the List dropdown and tap + to add the book to it.</p>
    <h3>Dropbox links</h3>
    <p>When a book has a file in Dropbox, its details show a small Open in Dropbox button. Next to it is a link to Open Library or Google Books, whichever the book's details came from. The Dropbox link opens the file in a new tab so you can read or download it.</p>
    <h3>Passcode</h3>
    <p>Bookshelf asks for a passcode the first time you visit on a device. Once you enter it, the device is remembered for a year, so you only enter it once per device.</p>
    <h3>Installing the app on a phone</h3>
    <p>On a phone, open Bookshelf in the browser, then use the browser menu and choose Add to Home screen or Install app. It then opens full screen like any other app, with its own icon.</p>
  </div>
</div>

<div id="flipOverlay" class="flipoverlay" hidden>
  <div class="flipstage"><div class="flipcard" id="flipCard"></div></div>
</div>

<script>
var state = {
  books: [],
  lists: [],
  search: "",
  sort: "title",
  dir: "asc",
  reader: "All",
  genre: "",
  readFilter: "all",
  view: "spine",
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

// Link to the site the book's details came from, when that is known:
// Open Library for books enriched there, Google Books for the few
// that came from the Watch List. Anything else has no source link.
function sourceLink(book) {
  var q = encodeURIComponent(((book.title || "") + " " + (book.author || "")).trim());
  if (book.enriched === "openlibrary") return { label: "Open Library", url: "https://openlibrary.org/search?q=" + q };
  if (book.enriched === "watchlist") return { label: "Google Books", url: "https://books.google.com/books?q=" + q };
  return null;
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

// Randy's genre table: the 28 genres in the Filters popup, and the
// subgenre each stored genre belongs to. A filter match is
// hierarchical, not substring: Fiction matches Historical Fiction,
// Classics and Magical Realism, but not Detective Fiction, which
// belongs to Mystery & Crime.
var GENRES = [
  "Fiction",
  "Mystery & Crime",
  "Thriller & Suspense",
  "Science Fiction",
  "Fantasy",
  "Horror",
  "Romance",
  "Action & Adventure",
  "Western",
  "Biography & Memoir",
  "History",
  "Politics & Society",
  "Business & Economics",
  "Self-Help & Personal Development",
  "Psychology & Philosophy",
  "Religion & Spirituality",
  "Health & Wellness",
  "Science & Nature",
  "Travel & Geography",
  "Food & Cooking",
  "Arts & Culture",
  "Sports & Recreation",
  "Education & Reference",
  "Family & Relationships",
  "Poetry & Drama",
  "Children's Books",
  "Young Adult",
  "Graphic Literature",
];

var SUBGENRE_PARENT = {
  "adventure": "Action & Adventure",
  "ancient history": "History",
  "architecture and design": "Arts & Culture",
  "art and photography": "Arts & Culture",
  "astronomy": "Science & Nature",
  "autobiography": "Biography & Memoir",
  "biography": "Biography & Memoir",
  "business": "Business & Economics",
  "canadian history": "History",
  "christianity": "Religion & Spirituality",
  "classics": "Fiction",
  "comics": "Graphic Literature",
  "communication": "Self-Help & Personal Development",
  "contemporary fiction": "Fiction",
  "contemporary romance": "Romance",
  "cookbooks": "Food & Cooking",
  "cosmic horror": "Horror",
  "cozy mystery": "Mystery & Crime",
  "current affairs": "Politics & Society",
  "cyberpunk": "Science Fiction",
  "dark fantasy": "Fantasy",
  "detective fiction": "Mystery & Crime",
  "domestic thriller": "Thriller & Suspense",
  "drama and plays": "Poetry & Drama",
  "dystopian": "Science Fiction",
  "early readers": "Children's Books",
  "economics": "Business & Economics",
  "education": "Education & Reference",
  "environment and climate": "Science & Nature",
  "epic fantasy": "Fantasy",
  "espionage": "Thriller & Suspense",
  "ethics": "Psychology & Philosophy",
  "fairy tales and folklore": "Fantasy",
  "film and television": "Arts & Culture",
  "finance and investing": "Business & Economics",
  "fitness": "Health & Wellness",
  "food writing": "Food & Cooking",
  "gothic horror": "Horror",
  "graphic novels": "Graphic Literature",
  "hard science fiction": "Science Fiction",
  "hard-boiled": "Mystery & Crime",
  "health": "Health & Wellness",
  "high fantasy": "Fantasy",
  "historical fiction": "Fiction",
  "historical romance": "Romance",
  "language and linguistics": "Education & Reference",
  "leadership and management": "Business & Economics",
  "legal thriller": "Mystery & Crime",
  "literary fiction": "Fiction",
  "magical realism": "Fiction",
  "manga": "Graphic Literature",
  "medical thriller": "Mystery & Crime",
  "medieval history": "History",
  "memoir": "Biography & Memoir",
  "mental wellness": "Health & Wellness",
  "middle grade": "Children's Books",
  "military fiction": "Action & Adventure",
  "military history": "History",
  "modern history": "History",
  "music": "Arts & Culture",
  "nature and wildlife": "Science & Nature",
  "outdoor recreation": "Sports & Recreation",
  "paranormal romance": "Romance",
  "parenting": "Family & Relationships",
  "personal growth": "Self-Help & Personal Development",
  "philosophy": "Psychology & Philosophy",
  "picture books": "Children's Books",
  "poetry": "Poetry & Drama",
  "police procedural": "Mystery & Crime",
  "political thriller": "Thriller & Suspense",
  "politics and government": "Politics & Society",
  "post-apocalyptic": "Science Fiction",
  "productivity": "Self-Help & Personal Development",
  "psychological horror": "Horror",
  "psychological thriller": "Thriller & Suspense",
  "psychology": "Psychology & Philosophy",
  "reference": "Education & Reference",
  "relationships": "Family & Relationships",
  "religion": "Religion & Spirituality",
  "romantic comedy": "Romance",
  "romantic suspense": "Romance",
  "science": "Science & Nature",
  "self-help": "Self-Help & Personal Development",
  "short stories": "Fiction",
  "social issues": "Politics & Society",
  "sociology": "Politics & Society",
  "space opera": "Science Fiction",
  "spirituality": "Religion & Spirituality",
  "sports": "Sports & Recreation",
  "supernatural horror": "Horror",
  "survival": "Action & Adventure",
  "suspense": "Thriller & Suspense",
  "sword and sorcery": "Fantasy",
  "technology": "Science & Nature",
  "time travel": "Science Fiction",
  "travel": "Travel & Geography",
  "travel memoir": "Travel & Geography",
  "true crime": "Mystery & Crime",
  "urban fantasy": "Fantasy",
  "western fiction": "Western",
  "ya contemporary": "Young Adult",
  "ya fantasy": "Young Adult",
  "ya romance": "Young Adult",
  "ya science fiction": "Young Adult",
};

function normGenre(s) {
  return String(s || "").toLowerCase().replace(/&/g, "and").replace(/'/g, "").replace(/\\s+/g, " ").trim();
}

function genreMatches(book, filter) {
  var f = normGenre(filter);
  var genres = book.genres || [];
  for (var i = 0; i < genres.length; i++) {
    var g = normGenre(genres[i]);
    if (g === f) return true;
    if (SUBGENRE_PARENT[g] && normGenre(SUBGENRE_PARENT[g]) === f) return true;
  }
  return false;
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
    var key = sortKeyOf(book);
    if (!key) return "No author";
    var ch = key.charAt(0).toUpperCase();
    if (ch < "A" || ch > "Z") return "#";
    return ch;
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
    if (state.genre && !genreMatches(book, state.genre)) return false;
    if (state.readFilter === "read" && !book.is_read) return false;
    if (state.readFilter === "unread" && book.is_read) return false;
    return true;
  });
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
    if (state.genre && GENRES.indexOf(state.genre) === -1) state.genre = "";
    render();
    if (state.detailId !== null) renderDetail();
    if (!$("listsOverlay").hidden) renderLists();
  });
}

function renderGenreOptions() {
  var sel = $("genreSel");
  var current = state.genre;
  var html = '<option value="">All genres</option>';
  GENRES.forEach(function (g) {
    html += '<option value="' + esc(g) + '"' + (g === current ? " selected" : "") + ">" + esc(g) + "</option>";
  });
  sel.innerHTML = html;
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

var SPINE_COLORS = ["#7a3b2e", "#2e4a6b", "#3f5a3a", "#6b5a2e", "#5a2e5a", "#2e5a52", "#8a5a2e", "#4a3b2e", "#31456b", "#6b2e3a", "#3a5a6b", "#5a6b2e", "#71463a", "#39597a"];

// One hash per book, so a book always gets the same spine colour and
// height wherever it sits.
function spineHash(book) {
  var s = String(book.title || "") + "|" + String(book.author || "");
  var h = 0;
  for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h;
}

function spineColor(book) { return SPINE_COLORS[spineHash(book) % SPINE_COLORS.length]; }

function spineHeight(book) { return 150 + (spineHash(book) % 31); }

function spineBoxHtml(book, width) {
  var w = width ? ";width:" + width.toFixed(3) + "px" : "";
  var html = '<button type="button" class="spine" data-book-id="' + book.id + '" style="background:' + spineColor(book) + ";height:" + spineHeight(book) + "px" + w + '" aria-label="' + esc(book.title) + " by " + esc(book.author || "") + '">';
  html += '<span class="spinetext"><span class="spinetitle">' + esc(book.title) + '</span><span class="spineauthor">' + esc(book.author || "") + "</span></span>";
  if (book.is_read) html += '<span class="spinecheck" aria-label="Read">&#10003;</span>';
  html += "</button>";
  return html;
}

// Exact-fill spine layout for one shelf body width. The spines on a
// full shelf share the body width exactly, so spines plus 2px gaps
// equal the body width with no leftover space at the end. One more
// spine fits than at the old 36px width, so the spines come out a
// little thinner. Never thinner than 32px, so the two-line spine text
// stays readable: if one more would go under 32px, fit one fewer
// instead. The 32px floor below that only bites on a screen too
// narrow for four readable spines, which no real phone reaches.
function spineLayoutFor(bodyW) {
  var per = Math.max(4, Math.floor((bodyW + 2) / 38));
  var count = per + 1;
  var width = (bodyW - 2 * (count - 1)) / count;
  if (width < 32) {
    count = per;
    width = (bodyW - 2 * (count - 1)) / count;
  }
  if (width < 32) width = 32;
  return { count: count, width: width };
}

// The layout for the shelf on this screen. The shelf body has no
// padding on its sides (10px on top only), inside a wrap with 14px of
// padding on each side, so the spines run to the body's left and
// right edges. Without a measurable layout (for example in a test)
// the full width desktop shelf is used.
function spineLayout() {
  var w = 0;
  var wrap = document.querySelector(".wrap");
  if (wrap && wrap.clientWidth) w = wrap.clientWidth - 28;
  else if (window.innerWidth) w = Math.min(window.innerWidth - 28, 692);
  if (!w || w < 100) w = 692;
  var layout = spineLayoutFor(w);
  layout.bodyW = w;
  return layout;
}

// How many spines fit across one shelf.
function spinesPerShelf() {
  return spineLayout().count;
}

// How wide each spine is on a full shelf.
function spineWidth() {
  return spineLayout().width;
}

function chunkShelves(sorted, per) {
  var n = per || spinesPerShelf();
  var chunks = [];
  for (var i = 0; i < sorted.length; i += n) chunks.push(sorted.slice(i, i + n));
  return chunks;
}

// The plaque key is what a shelf range is read from: the sort key for
// title, author and genre sorts, the year for date sorts.
function plaqueKeyOf(book) {
  if (state.sort === "release") return releaseYearOf(book);
  if (state.sort === "added") return addedYearOf(book);
  var k = sortKeyOf(book);
  return k || groupLabelOf(book);
}

function plaquePrefix(key, len) {
  var p = String(key || "").slice(0, len);
  if (p && /[a-z]/i.test(p.charAt(0))) p = p.charAt(0).toUpperCase() + p.slice(1);
  return p;
}

// Shortest prefix length that tells two keys apart, so the end of one
// shelf and the start of the next never read the same.
function diffPrefixLen(a, b) {
  var A = String(a || ""), B = String(b || "");
  var max = Math.max(A.length, B.length);
  for (var k = 1; k <= max; k++) {
    if (A.slice(0, k) !== B.slice(0, k)) return k;
  }
  return max;
}

// The plaque range for one shelf: first book to last book. The start
// of the first shelf and the end of the last shelf are one letter,
// since there is no neighbour to tell apart. Every other edge uses
// the shortest prefix that differs from the neighbouring shelf, so
// Albert to Billy then Buddy reads A - Bi and Bu - .... Date sorts
// show the full year range instead.
function plaqueRangeFor(chunks, i) {
  var first = chunks[i][0];
  var last = chunks[i][chunks[i].length - 1];
  var start, end;
  if (state.sort === "release" || state.sort === "added") {
    start = plaqueKeyOf(first) || "No date";
    end = plaqueKeyOf(last) || "No date";
    return start + " - " + end;
  }
  if (i === 0) {
    start = plaquePrefix(plaqueKeyOf(first), 1);
  } else {
    var prevLast = chunks[i - 1][chunks[i - 1].length - 1];
    start = plaquePrefix(plaqueKeyOf(first), diffPrefixLen(plaqueKeyOf(prevLast), plaqueKeyOf(first)));
  }
  if (i === chunks.length - 1) {
    end = plaquePrefix(plaqueKeyOf(last), 1);
  } else {
    var nextFirst = chunks[i + 1][0];
    end = plaquePrefix(plaqueKeyOf(last), diffPrefixLen(plaqueKeyOf(last), plaqueKeyOf(nextFirst)));
  }
  return start + " - " + end;
}

// First letters of the first and last book on a shelf, for the
// jump-to row: a letter jumps to the first shelf whose range holds it.
function rangeLoHi(chunk) {
  function firstLetter(key) {
    var ch = String(key || "").trim().charAt(0).toUpperCase();
    return (ch >= "A" && ch <= "Z") ? ch : "#";
  }
  var a = firstLetter(plaqueKeyOf(chunk[0]));
  var b = firstLetter(plaqueKeyOf(chunk[chunk.length - 1]));
  return { lo: a < b ? a : b, hi: a < b ? b : a };
}

function jumpLetterOf(label) {
  var ch = String(label || "").trim().charAt(0).toUpperCase();
  if (ch >= "A" && ch <= "Z") return ch;
  return "#";
}

function renderJumpTo(groups) {
  var present = {};
  groups.forEach(function (g) { present[jumpLetterOf(g.label)] = true; });
  var html = "";
  "#ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("").forEach(function (letter) {
    html += '<button type="button" class="jumpbtn" data-jump="' + letter + '"' + (present[letter] ? "" : " disabled") + ">" + letter + "</button>";
  });
  $("jumpto").innerHTML = html;
}

function render() {
  renderGenreOptions();
  var filtered = filteredBooks();
  var sorted = sortBooks(filtered);
  var total = state.books.length;
  if (filtered.length === total) {
    $("countLine").textContent = total === 1 ? "1 book." : total + " books.";
  } else {
    $("countLine").textContent = "Showing " + filtered.length + " of " + total + " books.";
  }
  $("empty").hidden = filtered.length !== 0;
  var html = "";
  if (state.view === "spine") {
    var layout = spineLayout();
    var chunks = chunkShelves(sorted, layout.count);
    var ranges = chunks.map(function (c, i) { return plaqueRangeFor(chunks, i); });
    renderJumpTo(chunks.map(function (c, i) { return { label: ranges[i], books: c }; }));
    chunks.forEach(function (chunk, i) {
      var loHi = rangeLoHi(chunk);
      html += '<section class="spineshelf"><div class="plaque" data-lo="' + esc(loHi.lo) + '" data-hi="' + esc(loHi.hi) + '">' + esc(ranges[i]) + "</div>";
      html += '<div class="spinebody"><div class="spinerow">';
      chunk.forEach(function (book) { html += spineBoxHtml(book, layout.width); });
      html += "</div></div>";
      html += '<div class="shelfboard"></div></section>';
    });
  } else {
    var groups = groupBooks(sorted);
    renderJumpTo(groups);
    groups.forEach(function (group) {
      html += '<section class="shelf"><h2 class="shelfhead">' + esc(group.label) + ' <span class="count">(' + group.books.length + ")</span></h2>";
      html += '<div class="shelfbody">';
      html += '<div class="grid">';
      group.books.forEach(function (book) { html += coverBoxHtml(book); });
      html += "</div>";
      html += "</div>";
      html += '<div class="shelfboard"></div></section>';
    });
  }
  $("shelves").innerHTML = html;
}

// ---- Detail overlay ----

function formatRating(r) {
  if (r === null || r === undefined) return "";
  return Number(r).toFixed(1);
}

function metaRow(label, value) {
  return '<div class="metarow"><span class="metalabel">' + esc(label) + '</span><span>' + esc(value) + "</span></div>";
}

function starStepsHtml(rating) {
  var pct = rating ? (rating / 5 * 100) : 0;
  var html = '<div class="stars" role="group" aria-label="My rating">';
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
  $("detailOverlay").hidden = false;
  renderDetail();
  if (window.requestAnimationFrame) window.requestAnimationFrame(layoutDetail);
}

function closeDetail() {
  state.detailId = null;
  detailEditing = false;
  $("detailOverlay").hidden = true;
}

var detailEditing = false;

// How many leading detail sections fit beside the cover. A section
// that would take the column past the bottom edge of the cover moves
// below the cover whole, with the sections after it, so a label and
// its value never split apart.
function splitDetailSections(coverHeight, sectionHeights) {
  var n = 0;
  var used = 0;
  for (var i = 0; i < sectionHeights.length; i++) {
    if (used + sectionHeights[i] > coverHeight) break;
    used += sectionHeights[i];
    n++;
  }
  return n;
}

// Move detail sections between the column beside the cover and the
// full-width area below it, using real rendered heights. Sections are
// measured back in the narrow column first, so the split follows the
// sizes on this screen. Runs after every detail render, again once the
// dialog is visible, again when the cover image finishes loading, and
// on resize while the dialog is open. It must only run while the
// dialog is visible: hidden, every height reads as zero and every
// section stays beside the cover.
function layoutDetail() {
  var body = $("detailBody");
  if (!body) return;
  var top = body.querySelector(".detailtop");
  var under = body.querySelector(".detailunder");
  if (!top || !under) return;
  var main = top.querySelector(".detailmain");
  var cover = top.querySelector(".detailcover");
  if (!main) return;
  var sections = Array.prototype.slice.call(body.querySelectorAll(".detailsection"));
  if (!sections.length) return;
  // Do not move sections while an edit field has focus. Re-parenting a
  // focused input dismisses the soft keyboard on a phone: opening the
  // keyboard fires a resize, which calls this again, so the layout
  // stays exactly where it is until the field is blurred. The first
  // placement is unaffected: renderDetail runs this before focus is set.
  var ae = document.activeElement;
  if (ae && (ae.id === "editTitle" || ae.id === "editAuthor")) return;
  sections.forEach(function (s) { main.appendChild(s); });
  var coverHeight = 0;
  if (cover) {
    coverHeight = cover.offsetHeight;
    if (!coverHeight) {
      var w = parseFloat(window.getComputedStyle(cover).width) || 110;
      coverHeight = w * 1.5;
    }
  }
  var heights = sections.map(function (s) { return s.offsetHeight; });
  var keep = splitDetailSections(coverHeight, heights);
  sections.slice(keep).forEach(function (s) { under.appendChild(s); });
}

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
    html += '<div class="detailsection" data-section="edit">';
    html += '<label class="fieldlabel" for="editTitle">Title</label>';
    html += '<input type="text" class="editinput" id="editTitle" maxlength="200" value="' + esc(book.title) + '">';
    html += '<label class="fieldlabel" for="editAuthor">Author</label>';
    html += '<input type="text" class="editinput" id="editAuthor" maxlength="120" value="' + esc(book.author || "") + '">';
    html += '<div class="editbtns"><button type="button" class="btn primary" data-action="save-title-author">Save</button>';
    html += '<button type="button" class="btn" data-action="cancel-title-author">Cancel</button></div>';
    html += "</div>";
  } else {
    html += '<div class="detailsection" data-section="title"><div class="detailtitlewrap"><h2 class="detailtitle">' + esc(book.title) + "</h2>";
    html += '<button type="button" class="btn small" data-action="edit-title-author">Edit</button></div></div>';
    html += '<div class="detailsection" data-section="author"><p class="detailauthor">' + esc(book.author || "") + "</p></div>";
  }
  var readLabel = book.is_read ? ("Read" + (book.read_on ? " on " + book.read_on : "")) : "Mark as read";
  html += '<div class="detailsection" data-section="rating"><div><span class="fieldlabel">My rating</span><div class="ratingrow">' + starStepsHtml(book.rating);
  html += '<button type="button" class="btn' + (book.is_read ? " primary" : "") + '" data-action="toggle-read" aria-pressed="' + (book.is_read ? "true" : "false") + '">' + esc(readLabel) + "</button></div>";
  html += "</div></div>";
  if (book.google_rating !== null && book.google_rating !== undefined) {
    var g = formatRating(book.google_rating);
    if (book.ratings_count) g += " (" + Number(book.ratings_count).toLocaleString("en-US") + ")";
    html += '<div class="detailsection" data-section="google">' + metaRow("Google rating", g) + "</div>";
  }
  var rel = String(book.published_date || "").trim() || (book.year ? String(book.year) : "");
  if (rel) html += '<div class="detailsection" data-section="release">' + metaRow("Release date", rel) + "</div>";
  if (book.page_count) html += '<div class="detailsection" data-section="pages">' + metaRow("Pages", String(book.page_count)) + "</div>";
  if (book.genres && book.genres.length) html += '<div class="detailsection" data-section="genres">' + metaRow("Genres", book.genres.join(", ")) + "</div>";
  if (book.publisher) html += '<div class="detailsection" data-section="publisher">' + metaRow("Publisher", book.publisher) + "</div>";
  html += "</div>";
  html += "</div>";
  html += '<div class="detailunder"></div>';
  if (book.description) html += '<p class="desc">' + esc(book.description) + "</p>";
  html += '<div class="detailactions">';
  html += '<div class="inlinerow"><span class="fieldlabel inline">Reader</span><select id="detailReader" class="narrowselect">';
  ["Randy", "Lisa", "All"].forEach(function (r) {
    html += '<option value="' + r + '"' + (book.reader === r ? " selected" : "") + ">" + r + "</option>";
  });
  html += "</select></div>";
  html += '<div class="inlinerow"><span class="fieldlabel inline">List</span>';
  if (state.lists.length) {
    html += '<select id="detailListSel" class="narrowselect" aria-label="Choose a list">';
    state.lists.forEach(function (l) { html += '<option value="' + l.id + '">' + esc(l.name) + "</option>"; });
    html += "</select>";
    html += '<button type="button" class="btn small" data-action="add-to-list" aria-label="Add to list">+</button>';
  } else {
    html += '<select disabled class="narrowselect" aria-label="Choose a list"><option>No lists yet</option></select>';
    html += '<button type="button" class="btn small" disabled aria-label="Add to list">+</button>';
  }
  html += "</div>";
  if (!state.lists.length) html += '<p class="muted">No lists yet. Create one from the Lists view first.</p>';
  var db = dropboxUrl(book.dropbox_path);
  var src = sourceLink(book);
  if (db || src) {
    html += '<div class="linkrow">';
    if (db) html += '<a class="btn small" href="' + esc(db) + '" target="_blank" rel="noopener noreferrer">Open in Dropbox</a>';
    if (src) html += '<a class="srclink" href="' + esc(src.url) + '" target="_blank" rel="noopener noreferrer">' + esc(src.label) + "</a>";
    html += "</div>";
  }
  html += "</div>";
  $("detailBody").innerHTML = html;
  layoutDetail();
  var coverImg = $("detailBody").querySelector(".detailcover");
  if (coverImg && !coverImg.complete) coverImg.addEventListener("load", layoutDetail);
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

function setFiltersOpen(open) {
  $("filtersPanel").hidden = !open;
  $("filtersBtn").setAttribute("aria-expanded", open ? "true" : "false");
}
$("filtersBtn").addEventListener("click", function (e) {
  e.stopPropagation();
  setFiltersOpen($("filtersPanel").hidden);
});
$("filtersClose").addEventListener("click", function () { setFiltersOpen(false); });
document.addEventListener("click", function (e) {
  var panel = $("filtersPanel");
  if (!panel || panel.hidden) return;
  if (panel.contains(e.target) || e.target === $("filtersBtn")) return;
  setFiltersOpen(false);
});

$("jumpto").addEventListener("click", function (e) {
  var t = e.target.closest("[data-jump]");
  if (!t || t.disabled) return;
  var letter = t.getAttribute("data-jump");
  var heads = document.querySelectorAll(".shelfhead, .plaque");
  for (var i = 0; i < heads.length; i++) {
    var head = heads[i];
    var match = false;
    if (head.classList.contains("plaque")) {
      var lo = head.getAttribute("data-lo") || "";
      var hi = head.getAttribute("data-hi") || "";
      if (letter === "#") match = lo < "A" || lo > "Z";
      else match = lo <= letter && letter <= hi;
    } else {
      var first = head.textContent.trim().charAt(0).toUpperCase();
      match = letter === "#" ? (first < "A" || first > "Z") : (first === letter);
    }
    if (match) {
      if (head.scrollIntoView) head.scrollIntoView();
      return;
    }
  }
});

function updateTopBtn() {
  var y = window.scrollY || document.documentElement.scrollTop || 0;
  $("topBtn").hidden = y <= 400;
}
window.addEventListener("scroll", updateTopBtn);
$("topBtn").addEventListener("click", function () { window.scrollTo({ top: 0, behavior: "smooth" }); });

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

function setView(view) {
  state.view = view;
  $("coverView").classList.toggle("active", view === "cover");
  $("spineView").classList.toggle("active", view === "spine");
  closeFlip(false);
  render();
}
$("coverView").addEventListener("click", function () { setView("cover"); });
$("spineView").addEventListener("click", function () { setView("spine"); });

var resizeTimer = null;
window.addEventListener("resize", function () {
  if (resizeTimer) clearTimeout(resizeTimer);
  resizeTimer = setTimeout(function () {
    if (state.view === "spine") render();
    if (state.detailId !== null && !$("detailOverlay").hidden) layoutDetail();
  }, 150);
});

// The flip: tapping a spine slides the book out of the shelf and
// turns it around to show the cover. The card starts on its spine
// side, small and low, and turns to the cover side as it settles.
function openFlip(id) {
  var book = bookById(id);
  if (!book) return;
  var cover = safeCover(book.cover_url);
  var html = "";
  html += '<button type="button" class="flipface flipfront" data-flip-cover data-book-id="' + book.id + '" aria-label="' + esc(book.title) + " by " + esc(book.author || "") + '">';
  if (cover) {
    html += '<img src="' + esc(cover) + '" alt="">';
  } else {
    html += '<span class="nocover"><span class="nctitle">' + esc(book.title) + '</span><span class="ncauthor">' + esc(book.author || "") + "</span></span>";
  }
  if (book.is_read) html += '<span class="covercheck" aria-label="Read">&#10003;</span>';
  html += "</button>";
  html += '<div class="flipface flipback" style="background:' + spineColor(book) + '">';
  html += '<span class="spinetext"><span class="spinetitle">' + esc(book.title) + '</span><span class="spineauthor">' + esc(book.author || "") + "</span></span>";
  html += "</div>";
  $("flipCard").innerHTML = html;
  $("flipCard").classList.remove("open");
  $("flipOverlay").hidden = false;
  setTimeout(function () { $("flipCard").classList.add("open"); }, 30);
}

function closeFlip(animate) {
  if ($("flipOverlay").hidden) return;
  if (animate) {
    $("flipCard").classList.remove("open");
    setTimeout(function () { $("flipOverlay").hidden = true; }, 600);
  } else {
    $("flipOverlay").hidden = true;
  }
}

$("flipOverlay").addEventListener("click", function (e) {
  var coverBtn = e.target.closest("[data-flip-cover]");
  if (coverBtn) {
    var id = Number(coverBtn.getAttribute("data-book-id"));
    closeFlip(false);
    openDetail(id);
    return;
  }
  if (!e.target.closest(".flipcard")) closeFlip(true);
});

$("shelves").addEventListener("click", function (e) {
  var t = e.target.closest("[data-book-id]");
  if (!t) return;
  var id = Number(t.getAttribute("data-book-id"));
  if (state.view === "spine") openFlip(id);
  else openDetail(id);
});

$("detailBody").addEventListener("click", function (e) {
  var t = e.target.closest("[data-action]");
  if (!t) return;
  var action = t.getAttribute("data-action");
  var book = bookById(state.detailId);
  if (!book) return;
  if (action === "close-detail") closeDetail();
  else if (action === "set-rating") {
    var v = parseFloat(t.getAttribute("data-rating"));
    if (v === 0.5 && book.rating === 0.5) saveRating(book, null);
    else saveRating(book, v);
  }
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
    if (b.parentElement.id === "listsOverlay") closeLists();
    else if (b.parentElement.id === "aboutOverlay") $("aboutOverlay").hidden = true;
  });
});

document.addEventListener("keydown", function (e) {
  if (e.key !== "Escape") return;
  if (!$("detailOverlay").hidden) closeDetail();
  else if (!$("listsOverlay").hidden) closeLists();
  else if (!$("aboutOverlay").hidden) $("aboutOverlay").hidden = true;
  else if (!$("filtersPanel").hidden) setFiltersOpen(false);
  else if (!$("flipOverlay").hidden) closeFlip(true);
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

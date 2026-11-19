# Bookshelf

Bookshelf is the private book collection app for Randy and Lisa. It shows
every book that has been loaded into the collection, grouped into shelves,
with cover and list views, star ratings, read marks, reader labels, custom
lists, and a link to the file in Dropbox.

## Files

- `worker.js`: the whole app. One Cloudflare Worker, no dependencies, no
  build step. It serves the page, the JSON API, and the installable-app
  files (manifest, service worker, icon).
- `wrangler.jsonc`: Worker config. Name `bookshelf`, D1 binding `DB`,
  database `bookshelf`. No cron triggers in v1.
- `schema.sql`: a copy of the live D1 schema, as applied.
- `package.json`: private package with a `check` script that runs
  `node --check worker.js`.

## Data tables

All data lives in the D1 database `bookshelf` (binding `DB`).

- `books`: one row per book. Title, author, year, reader (Randy, Lisa, or
  All), read mark (`is_read`) with the date marked (`read_on`), star
  rating, genres and formats (JSON arrays stored as text), cover URL,
  description, page count, publisher, published date, Google rating and
  ratings count, ISBN, language, info link, Dropbox path, filename,
  format, and added/created/updated timestamps.
- `lists`: named custom lists.
- `list_items`: which books sit in which list, and in what order
  (`position`).
- `device_tokens`: passcode device tokens, one per unlocked device.
- `unlock_attempts`: failed passcode guesses, used for the rate limit.
- `settings`: key and value settings, unused in v1.

Books are loaded by an import job, not through this app. The app only
reads books and records read marks, star ratings, reader labels, and
custom lists.

## Passcode gate

The gate is fail-open until the `SITE_PASSCODE` secret is set. Once set,
the first visit from a device shows a code box instead of the shelves. A
correct code earns the device a remembered token, kept in a cookie named
`bs_auth` for one year, so the code is only entered once per device. The
cookie name differs from the Watch List gate on purpose, so the two gates
stay independent. Five wrong guesses per hour from one sender returns a
429 and locks that sender out until the hour passes. The service worker,
manifest, icon, and favicon are exempt from the gate, as is the unlock
endpoint. Every other route needs a valid token.

## Dropbox link

The detail view shows an Open in Dropbox link when a book has a
`dropbox_path` stored. The link is built as
`https://www.dropbox.com/preview` plus the stored path, with each path
segment URL-encoded. For example, a path of `/books/Randy/My Book.epub`
becomes `https://www.dropbox.com/preview/books/Randy/My%20Book.epub`.
The link opens in a new tab. When a book has no Dropbox path, no link
is shown.

## Cache version

The service worker cache is named `bookshelf-v1`. When the app shell
changes in a way old cached copies must not serve, bump the version in
the `CACHE` constant in `worker.js` (for example to `bookshelf-v2`) and
deploy. The new worker then clears the old cache on activation.

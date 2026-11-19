# Bookshelf

Bookshelf is the private book collection app for Randy and Lisa. It shows
every book that has been loaded into the collection, grouped into shelves,
with cover and spine views, star ratings, read marks, reader labels, custom
lists, and a link to the file in Dropbox.

## Views

Spine view is the default. It shows the books as
shelves of spines, like books on a real shelf, with a brass plaque in the
middle at the top of each shelf showing the first and last books on it. Each
spine shows the title and author on two lines. The spines on a shelf share
its width exactly, so a full shelf has no empty space at the end. The
plaque range follows the sort: letters for title, author and genre sorts,
with two or three letters when the shelf boundary needs them, and the year
range for release date and date added sorts. Tap a spine and the book slides
out of the shelf and turns around to show its cover. Tap the cover to open
the book's details. Tap anywhere else to put the book back on the shelf.
The details dialog only closes with its Close button. Cover view shows the
book covers in a grid. In a book's details, the cover sits on the left with
the title, rating, Google rating, release date, pages, genres, publisher,
and Read button beside it, in that order, while they fit. A section that
would run past the bottom of the cover moves under it whole, so a label and
its value never split apart. The description comes right after
the Read button, under the cover, then the Reader and List dropdowns and
the Dropbox and source links.

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
  Dropbox file id (`dropbox_id`), enrichment source (`enriched`:
  `openlibrary`, `watchlist`, or empty), format, and added/created/updated
  timestamps.
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
is shown. Next to the Dropbox button the details also show a link to
the site the book's details came from when that is known: Open Library
for books enriched from Open Library, Google Books for the few that
came from the Watch List. The link is a search for the book's title
and author on that site.

## Cache version

The service worker cache is named `bookshelf-v9`. When the app shell
changes in a way old cached copies must not serve, bump the version in
the `CACHE` constant in `worker.js` (for example to `bookshelf-v9`) and
deploy. The new worker then clears the old cache on activation.

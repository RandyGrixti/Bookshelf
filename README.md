# Bookshelf

Bookshelf is the private book collection app for Randy and Lisa. It shows
every book that has been loaded into the collection, grouped into shelves,
with cover and spine views, star ratings, read marks, reader labels, custom
lists, series views, editable book details, and a link to the file in Dropbox.

## Views

Spine view is the default. It shows the books as
shelves of spines, like books on a real shelf, with a brass plaque in the
middle at the top of each shelf showing the first and last books on it. Each
spine shows the title and author on two lines. Each spine carries one of four
designs, gold bands, chevrons, dots, or a two-tone top, picked per book and
kept the same every time you open the app. The spines on a shelf share
its width exactly, so a full shelf has no empty space at the end. The
plaque range follows the sort: short labels of two to four letters
from the first significant word for title, author and genre sorts,
with the word spelled out and the next word used when titles share
a word, and a shelf filled by one series shows the series name and
its book numbers instead. Title sorting ignores a leading A, An, or
The, reads a leading number as words, and ignores punctuation. The
year range is shown for release date and date added sorts. Tap a spine and the book slides
out of the shelf and turns around to show its cover. Tap the cover to open
the book's details. Tap anywhere else to put the book back on the shelf.
The details dialog only closes with its Close button. Cover view shows the
book covers in a grid. In a book's details, the cover sits on the left with
the title, the series name when the book belongs to a series, rating, Google rating, release date, year when a full date is also known, pages, genres, publisher, ISBN when one is known, and language when one is known,
and Read button beside it, in that order, while they fit. Tap the series
name to open a view of every book in the series in book-number order,
with books that have no number at the end in release-date order; tap a
book there to open its details. A section that
would run past the bottom of the cover moves under it whole, so a label and
its value never split apart. The description comes right after
the Read button, under the cover, then the Reader and List dropdowns and
the Dropbox and source links. Tap Edit beside the title to change the
book's details: title, author, series name, book number, cover photo, description, release date,
year, pages, publisher, ISBN, language, and genres. Tap Refresh beside Edit to look the book up again on the internet
(Hardcover first, then Google Books, then Open Library) and update its details and cover; the
refresh overwrites the pulled fields with fresh values, never touches the title, author, reader,
read mark, your rating, lists, or the locked flag, and works on locked books too. If no source
has a confident match for the title and author, the refresh says so and changes nothing. The Google rating is pulled from the
internet and is not editable. Changing only the title or author queues
a rename of the Dropbox file, and the book still refreshes from the
internet. Changing anything else turns automatic updates off for that
book, and a note in the details says so, with a button to turn updates
back on. A locked book still gets title and author changes from Dropbox
filenames, and still leaves the library when its file leaves Dropbox.
Series data (name and book number) comes from Hardcover, filled by
`~/workspace/book-library-build/fill_series.py` (migration 0006), and
can also be set by hand in the Edit form. Changing the series name or
book number turns automatic updates off for that book, the same as
changing any other field except the title or author. A series filled
by that script is never overwritten by a later run of it: it only
fills books whose series is still blank, so a hand-entered series
stays put. Series markers that were in a title
("Book 3", "- 09", "(Reckoners #3)") are cleaned out of the title
when Hardcover confirms that book's series, and the Dropbox file is
renamed to match on the next nightly check.

The About button opens the help. Its search box at the top filters
the sections to the ones that match, opening them so the match is
visible, and every section starts closed: tap a heading to open or
close it. The Back to top button appears at the bottom right when
you have scrolled down the shelves, and in the Lists view too when
you have scrolled down a list.

## Covers

Covers are saved in Bookshelf itself, in the R2 bucket `bookshelf-covers`
(binding `COVERS`). A cover's key is the book id, a short hash of the
image, and the extension, for example `253-90c35dd5185e.jpg`, and the
book's `cover_url` is the local path `/covers/253-90c35dd5185e.jpg`.
Replacing a cover always makes a new key, so a stale cached copy can
never show, and the old object is deleted. Covers are served from
`/covers/<key>` behind the same passcode gate as everything else, with a
one-year immutable cache. Upload a photo of a cover from the Edit form,
or click the paste box under the cover photo and paste an image; it must be a JPEG, PNG, or
WebP image of at most 5 MB. A pasted image shows as a small preview in
the form before saving. Books whose
covers have not been saved yet still show the old external cover link.
A refresh saves the best cover it finds (Hardcover, then Google Books,
then Open Library) into Bookshelf the same way, and every night at
4:00 AM BC the Worker fills in up to 20 books that still have no cover,
oldest added first, in the same lookup order; a book no source can find
a cover for is not retried every night. The Worker never stores a
remote cover link as a book's cover: a cover only counts once it has
been saved to R2.
The one-off move of the existing external covers into R2 is done by
`~/workspace/book-library-build/migrate_covers_to_r2.py`, which is
resumable, throttled, and takes its R2 credentials from environment
variables. Run it only after the bucket exists and this version is live.

## Files

- `worker.js`: the whole app. One Cloudflare Worker, no dependencies, no
  build step. It serves the page, the JSON API, the cover images, and the installable-app
  files (manifest, service worker, icon).
- `wrangler.jsonc`: Worker config. Name `bookshelf`, D1 binding `DB`,
  database `bookshelf`, R2 binding `COVERS`, bucket `bookshelf-covers`.
  A daily cron trigger at 11:00 UTC (4:00 AM BC) runs the Worker's
  scheduled handler, which fills in missing covers (see Covers).
  Optional secrets `HARDCOVER_API_KEY` and `GOOGLE_BOOKS_API_KEY`
  feed the refresh and the nightly cover fill; when either is missing
  its source is skipped, never failed.
- `schema.sql`: a copy of the live D1 schema, as applied.
- `package.json`: private package with a `check` script that runs
  `node --check worker.js`.

## Data tables

All data lives in the D1 database `bookshelf` (binding `DB`).

- `books`: one row per book. Title, author, year, reader (Randy, Lisa, or
  All), read mark (`is_read`) with the date marked (`read_on`), star
  rating, genres and formats (JSON arrays stored as text), cover URL,
  description, page count, publisher, published date, Google rating and
  ratings count, Hardcover rating and ratings count, ISBN, language, info link, Dropbox path, filename,
  Dropbox file id (`dropbox_id`), enrichment source (`enriched`:
  `openlibrary`, `watchlist`, or empty), format, `locked` (1 when a hand
  edit has turned automatic updates off for the book, migration 0005),
  `cover_checked_at` (when the nightly cover fill last tried this book,
  migration 0010), and added/created/updated timestamps.
- `lists`: named custom lists.
- `list_items`: which books sit in which list, and in what order
  (`position`). In Edit mode each book shows its position number;
  typing new numbers and tapping Save order reorders the list through
  the `/api/lists/reorder` endpoint (the up and down buttons still
  work too), and a blank or invalid number leaves that book where
  it was.
- `pending_deletes`: books deleted in the app whose Dropbox file still
  waits for the nightly move to the review for deletion folder
  (migration 0007). Each row keeps the book id, Dropbox file id, path,
  and filename, so the nightly sync can move the file and then clear
  the row.
- `pending_moves`: books whose Reader changed in the app and whose
  Dropbox file still waits for the nightly move to the matching folder
  (migration 0008). Each row keeps the book id, target folder, Dropbox
  file id, path, and filename, so the nightly sync can move the file
  and then clear the row. A second Reader change replaces the queued
  row, so the latest Reader wins.
- `device_tokens`: passcode device tokens, one per unlocked device.
- `unlock_attempts`: failed passcode guesses, used for the rate limit.
- `settings`: key and value settings, unused in v1.

Books are loaded by an import job, not through this app. The app only
reads books and records read marks, star ratings, reader labels, custom
lists, and detail edits. Deleting a book in the app removes its row at
once and queues its Dropbox file for the nightly move to the review
for deletion folder; the nightly sync moves the file and clears the
queue row, and never re-adds a file that is still queued for deletion.
Changing a book's Reader in the app updates the label at once and
queues its Dropbox file for the nightly move to the matching folder
(Randy, Lisa, or All); the nightly sync moves the file, updates the
row's path, and clears the queue row, and never treats a file still
queued for a move as a new book. A file with the same name already
sitting at the destination blocks the move instead of being renamed:
the row stays queued and the nightly summary reports it.
The nightly sync refreshes a book's details
from the internet when its title or author changes, but never refreshes
a book with `locked` set; it still applies title and author changes
from Dropbox filenames to locked books, and still removes a locked book
when its file leaves Dropbox.

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

The service worker cache is named `bookshelf-v26`. When the app shell
changes in a way old cached copies must not serve, bump the version in
the `CACHE` constant in `worker.js` (for example to `bookshelf-v27`) and
deploy. The new worker then clears the old cache on activation.

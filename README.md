# SRM Find – Campus Lost & Found

A simple website where students can post items they lost or found on campus.
It uses the same Java classes as the original console program (`Item`, `LostItem`,
`FoundItem`, `Repository`, `Storage`, the match score), but serves a web page
instead of a text menu. It needs no extra libraries, only Java.

## How to run

```bash
cd SRMFind
javac Main.java
java Main
```

Then open http://localhost:8080 in your browser.

## Features

- **Sign up / log in** with a college email (`.edu` or `.edu.in`). Passwords are stored as salted SHA-256 hashes.
- **Report lost item / report found item.** As soon as you post, the site shows possible matches (score ≥ 60%)
  with the score breakdown: category +40, name +40 (exact) or +20 (partial), location +20.
- **Two-party handover.** The owner and the finder each confirm with their registered email. The match score is
  checked again, then both reports change from ACTIVE to RESOLVED together. Anyone else is rejected with "Verification failed!".
- **Notifications** (bell icon) for new matches on your reports and for handovers waiting for your confirmation.
- **O(1) lookup**: searching for a report ID like `L101` uses the repository's HashMap directly.
- **Browse**: search by name, place or ID, filter by Lost/Found, category and status, and sort by newest or by name.
- **Contact** the finder or owner by email, then meet them and get the item.
- **My reports**: edit, delete, see matches, or mark the item resolved. Marking a match as resolved closes both reports.
- **Dashboard** counts: total, lost, found, and returned.
- **Photo upload** (optional) when reporting or editing an item. The browser shrinks photos before uploading them.

## Where the data is stored

Everything is saved in the `data/` folder next to `Main.java`:

| File | What it is |
|---|---|
| `data/reports.csv` | All reports in a readable form. Double-click to open in Numbers or Excel. |
| `data/users.csv` | Registered users (name and email; passwords are not included) |
| `data/photos/` | The uploaded item photos |
| `data/srmfind.dat` | The actual database the program loads (Java serialization, not readable) |

The CSV files are rewritten every time something changes. Editing them does not change the
website, because the program only reads `srmfind.dat`.

## Files

- `Main.java`: the Java backend (model classes, matching logic, login, and the web server)
- `public/index.html`: the web page (HTML, CSS and JavaScript)

## Deployment (Vercel)

The site runs on Vercel as a container built from `Dockerfile.vercel` (Java 21).
Vercel's container disk is temporary, so when the `BLOB_READ_WRITE_TOKEN` environment
variable is set, the server saves `srmfind.dat` and the photos in a **private Vercel Blob store**
instead of the `data/` folder:

- `srmfind/srmfind.dat`: the serialized `Storage` object (same Java serialization as locally)
- `srmfind/photos/…`: item photos, served through the Java server

Logins use a signed (HMAC-SHA256) cookie, so users stay logged in when Vercel restarts the server.
Every push to `main` on GitHub deploys automatically.

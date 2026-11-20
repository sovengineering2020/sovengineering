# SOV Engineering Factory Manager

Admin Attendance time saves treat blank In-Time and Out-Time fields as explicit clears. The Worker Dashboard supports selected-date views from active and completed Work Orders. My Work remains the existing fixed-today view and save workflow.

This package contains the application source and the Admin-controlled synchronization update.

## Files

- `server.js` — Express API, authentication, validation, GitHub year-wise persistence, and single pending operation file
- `index.html` — browser application
- `package.json` — Node.js package metadata and dependencies
- `.env.example` — placeholder environment settings
- `sov-logo.svg` — supplied application logo
- `.gitignore`

## Storage and synchronization

Operational module records are stored in year-wise JSON documents at `data/records/sov_YYYY.json` in the configured GitHub repository. All pending changes are stored in exactly one durable file: `data/pending.json`. Each operation includes a unique operation ID, record ID, module, operation type, changed values, calendar year, original record reference when applicable, timestamps, and synchronization status. Repeated changes are coalesced by record ID except when a synchronization snapshot is in flight; later changes remain pending independently.

At startup, the server verifies GitHub repository access, ensures the `data/records/` directory exists, and validates or creates only `data/pending.json`. GitHub does not store empty directories, so a `.gitkeep` marker is created only when `data/records/` itself is missing. Startup and Admin login do not create year files. The first confirmed synchronization for a record year creates `data/records/sov_YYYY.json` with the appropriate schema; existing year files are read and updated with SHA checks and read-back verification. Existing valid files are never replaced. Invalid JSON/schema, authentication, permission, repository, rate-limit, and network errors are logged and returned as storage errors from business-data APIs rather than treated as empty data. A temporary startup storage failure does not prevent the authentication server from starting; the pending check retries initialization after Admin login.

Only a new successful Admin login checks `data/pending.json`. If valid pending changes exist, a branded confirmation dialog offers Cancel or OK – Update Now. Changes created during the current session are retained for the next Admin login. Cancel leaves operations pending. Confirmed synchronization groups operations by year, uses GitHub branch and SHA concurrency checks, retries bounded conflicts, verifies read-back, and clears only successfully verified operation IDs. Changes created during synchronization are preserved, failed operations remain retryable, and the single pending file remains present with an empty collection after complete success.

CSV remains for backup/export only. Startup does not restore CSV or the former partitioned business-data store and does not migrate old data. Existing CSV files are left untouched. No module/month business files are created in `data/records`.

Employee authentication and employee JSON storage retain their existing dedicated flow. The year-wise `sov_YYYY.json` files contain the operational modules served through the state API.

## Run locally

1. Use Node.js 18 or newer.
2. Copy `.env.example` to `.env` and set unique values for `ADMIN_PIN`, `COMMON_DASHBOARD_PIN`, `CSV_ENCRYPTION_KEY`, `SOV_AUTH_SECRET`, and `DATA_ENCRYPTION_KEY`. `DATA_ENCRYPTION_KEY` accepts either a 64-character hex key or a private text passphrase at least 16 bytes long. Text passphrases are strengthened with scrypt and a random salt for each stored document. Store the value only in the backend deployment secret store.
3. Configure `GITHUB_TOKEN`, `GITHUB_REPO`, and `GITHUB_BRANCH` for a private repository with Contents read/write access.
4. Run `npm install` and `npm start`.
5. Open `http://localhost:3000`.

Never commit `.env` or share its secrets. Live GitHub synchronization requires repository credentials.

## GitHub business-data encryption and key rotation

Year-wise documents and `data/pending.json` are encrypted on the server with AES-256-GCM before GitHub writes. Every write uses a fresh 12-byte random IV and stores the version, key identifier, IV, authentication tag, and ciphertext. The server validates the GCM tag and JSON schema before using data. Missing, plaintext, malformed, or undecryptable existing files are never replaced with empty data. `DATA_ENCRYPTION_KEY` is required for business storage; authentication remains available if storage cannot initialize.

For Render, open the SOV Engineering web service Environment settings, add `DATA_ENCRYPTION_KEY` with the same 64-character hex key or 16+ byte text passphrase used by the deployment, and redeploy or restart the service. Do not paste the key into the browser, GitHub, or chat. The application reports this missing setting as a storage-configuration notice rather than an invalid login or browser console exception. Until the setting is present, business records and pending updates intentionally remain unavailable; no plaintext fallback is used.

Keep the current key stable across all running instances and deployments. For rotation, set the new key as `DATA_ENCRYPTION_KEY` and add the old hex key or text passphrase to `DATA_ENCRYPTION_PREVIOUS_KEYS` (comma-separated if more than one; do not use commas inside a passphrase). Deploy that configuration first so all instances can read both key generations. Then sign in as the main Admin and call the authenticated `POST /api/admin/reencrypt-storage` endpoint; it rewrites existing year files and the pending journal with the current key using GitHub SHA checks and read-back verification. Keep prior keys configured until the endpoint reports success and a backup has been secured; then remove old keys. Do not remove the only key that can decrypt any existing file.

## Validation

Run `npm run check` for backend syntax. The browser script and package JSON are also parsed before delivery. Live GitHub concurrency and read-back require a configured private repository and were not integration-tested in this environment.

## Requested admin enhancements

- Invoice/DC Saved Records and Outward Invoice reports display the Customer DC Number in its own column. Legacy “customerDc” values remain readable.
- Employee records support a relieving date. Daily attendance and active employee selection stop including the employee on that date and later, while date-filtered historical records remain available. Relieving dates can be set to today or a future date; clearing the field removes the relieving date.
- Employee deletion is limited to the Main Admin role, uses a confirmation step, then verifies the Main Admin PIN on the server. The employee is tombstoned so old employee relationships and historical reports remain intact.
- Job Status uses the same selected-date logic on Dashboard and Reports: a row requires saved activity for that date, and a completed job is excluded after its saved completion date.
- The Admin Panel includes Parts Amount Details with add/edit/soft-delete and part-number search, plus separately managed Invoice and DC templates. Invoice/DC templates customize only workbook-marked To/customer fields; SOV Engineering From details are fixed. Invoice/DC preview can be opened from the Invoice/DC form and printed or saved as PDF from the browser print dialog.

Invoice and Delivery Challan previews render from the latest supplied `Book1.xlsx` sample sheets. The project includes the printable cell layout, merged ranges, row/column sizing, workbook styles, and embedded DC logo in `excel-reference-layouts.json` and `sample-dc-logo.png`. Both previews use A4 portrait sizing and retain the original cell arrangement. The DC logo is scaled proportionally to fit its reference box. HSN values from existing job-part records populate the common HSN column in both templates without adding an HSN entry field to the Invoice/DC form. Values in dynamically generated part rows are centered in both templates; all other sections retain workbook alignment. Existing Weight and UOM data remain preserved in saved records and template output without adding entry fields. DC quantities use two decimal places, and invoice currency amounts use two decimal places. Preview and PDF output use the browser print dialog, so the final printer/PDF driver still controls physical output scaling. Saved Invoice/DC records load their saved transaction details in Edit, place company-template selection immediately before Preview / Print, and can be previewed/printed without saving first. Customer DC and PO dates each support Date/None; the date input is hidden when None is selected and is suppressed when the paired reference number is NA.

## Invoice/DC reference templates (latest workbook)

The Invoice and DC preview templates use the supplied `Book1.xlsx` sheets as their layout source, including cell styling, merged ranges, dimensions, and the embedded DC logo. Template configuration is separate by document type. Invoice customizes the marked To name, three address lines, and GST number. DC customizes the marked To name, multiline address, and GST number. The template name is derived from the To name. SOV Engineering company name, From address, logo, and all unmarked reference content remain fixed. The transaction-entry page has no editable address box; selecting a saved template fills the hidden transaction address used for preview and records.

Document previews use A4 portrait and fit the reference layout and item rows onto one page by scaling the row heights and typography together. Additional item rows clone the final reference item-row styling and merged cells. If a document exceeds the minimum readable one-page scale, generation is stopped with a clear message rather than silently clipping content. Use the browser's PDF/print output at A4 size with scaling set to fit the page.


## Invoice/DC entry form template behavior

For Outwards Invoice/DC entries, the template picker and Preview / Print control appear immediately above Save. Inwards and Purchase Order entries do not show template controls. Selecting an Outwards template fills its To address and GST into hidden record fields; the template's To name/address/GST remain read-only on the entry form. The separate Company Name field is report-only. Repeated Customer GST and Approximate DC Value inputs are hidden for Outwards Invoices; Customer PO reference/date and Our DC inputs are hidden for Outwards DCs. Approximate DC Value remains available for DC entries. Template preview windows allow vertical and horizontal scrolling on desktop; print retains A4 layout.

Outwards entry behavior keeps template-owned To name, address, and GST read-only. The entry page's Company Name is stored for reports only and is not used to change the selected template. Approximate DC Value is hidden for Invoice; Customer PO reference/date and Our DC are hidden for DC; Customer GST is hidden for both Outwards document types. Inwards and Purchase Order keep their existing transaction inputs and omit the template print controls. Preview windows scroll vertically and horizontally on desktop while print output retains its A4 page settings.

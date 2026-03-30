# Releasing Qrypto

## 1. Commit your changes

```bash
git add .
git commit -m "your commit message"
```

## 2. Create a git tag

Always use an **annotated tag** for releases. An annotated tag is a full git object that stores your name, date, and a message — unlike a plain `git tag` which is just a nameless pointer to a commit with no extra info.

```bash
git tag -a v1.0.0 -m "v1.0.0"
```

Keep the tag message short — just the version. The full release notes go in the GitHub release (step 4).

### Tagging a specific past commit

By default, the tag points to your current (latest) commit. To tag an older commit:

```bash
# find the commit hash
git log --oneline

# tag a specific commit
git tag -a v1.0.1 <commit-hash> -m "v1.0.1"
```

## 3. Push to GitHub

Tags are not pushed automatically with commits — they must be pushed separately.

```bash
git push origin main
git push origin v1.0.0
```

Or push commits and all tags in one shot:

```bash
git push origin main --tags
```

## 4. Create the GitHub release

The GitHub release is where you write full release notes. Keep the tag message short and put the detail here.

**Option A — auto-generate notes from commit messages (recommended):**
```bash
gh release create v1.0.0 --title "v1.0.0" --generate-notes
```

**Option B — write notes inline:**
```bash
gh release create v1.0.0 --title "v1.0.0" --notes "$(cat <<'EOF'
## What's new
- Added `show` command to display QR codes in terminal
- Fixed build backend for pipx compatibility

## Install
pipx install git+https://github.com/ameenfarook8/qrypto.git@v1.0.0
EOF
)"
```

**Option C — write notes from a file:**
```bash
gh release create v1.0.0 --title "v1.0.0" --notes-file CHANGELOG.md
```

**Option D — on GitHub manually:**
Releases → Draft a new release → pick tag → Publish release

---

## Installing a release via pipx

```bash
# Latest from main branch
pipx install git+https://github.com/ameenfarook8/qrypto.git

# Specific release tag
pipx install git+https://github.com/ameenfarook8/qrypto.git@v1.0.0
```

> `@latest` is not a valid tag — git has no built-in latest keyword. Omitting the tag always installs from `main`.

## Upgrading

```bash
pipx upgrade qrypto
```

> Note: if installed with a specific tag (`@v1.0.0`), upgrade won't move to a newer tag.
> Uninstall and reinstall with the new tag instead:
> ```bash
> pipx uninstall qrypto
> pipx install git+https://github.com/ameenfarook8/qrypto.git@v2.0.0
> ```

## Uninstalling

```bash
pipx uninstall qrypto
```

---

## Version checklist

- [ ] Update `version` in `pyproject.toml`
- [ ] Commit all changes
- [ ] Tag the commit (`git tag -a vX.Y.Z -m "vX.Y.Z"`)
- [ ] Push commits and tag (`git push origin main --tags`)
- [ ] Create GitHub release (`gh release create vX.Y.Z --generate-notes`)

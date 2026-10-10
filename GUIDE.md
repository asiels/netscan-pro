# NetScan Pro — Step-by-Step Publishing Guide

From zero to a live GitHub repo with working CI, in about 30 minutes.

---

## STEP 0 — Get the project files onto your machine (~2 min)

The project currently lives in this chat's sandbox at:
    /mnt/agents/output/netscan_pro/

Download that entire folder to your computer (use the download option on the
folder/files shown in this chat, or copy each file). Keep the structure:

    netscan_pro/
    ├── netscan/  tests/  .github/  ...etc

> Tip: keep the hidden files too — `.gitignore`, `.pre-commit-config.yaml`,
> and `.github/workflows/ci.yml` start with a dot and are easy to miss.

---

## STEP 1 — Prerequisites (~5 min)

1. **Python 3.9 or newer**
       python3 --version
   (3.11+ recommended; comes with everything needed)

2. **Git**
       git --version

3. **A GitHub account** — sign up free at https://github.com if needed.

4. (Optional but recommended) **GitHub CLI** `gh` for repo creation from the
   terminal: https://cli.github.com — or just use the GitHub website instead.

---

## STEP 2 — Set up the project locally (~5 min)

Open a terminal in the `netscan_pro` folder, then:

```bash
# 2.1  Create an isolated virtual environment
python3 -m venv .venv

# 2.2  Activate it
source .venv/bin/activate            # macOS / Linux
# .venv\Scripts\activate           # Windows (CMD)

# 2.3  Install the package + dev tools (this gives you the `netscan` command)
pip install -e ".[dev]"

# 2.4  Install the git hooks (auto-lint before every commit)
pre-commit install
```

You should now be able to run:

```bash
netscan --version        # -> netscan 2.0.0
```

---

## STEP 3 — Prove it works: run the tests (~2 min)

```bash
pytest
```

Expected: all tests PASS (23 tests). This is the exact same command CI runs.

Optional: scan the legal demo target (no root needed):

```bash
netscan -t scanme.nmap.org -p 1-512 --engine async
```

---

## STEP 4 — Create the GitHub repository (~3 min)

**Option A — GitHub website (easiest):**
1. Go to https://github.com/new
2. Repository name: `netscan-pro`
3. Choose **Public** (recruiters need to see it)
4. Do NOT check "Add a README" (you already have one)
5. Click **Create repository**

**Option B — GitHub CLI:**
```bash
gh repo create netscan-pro --public --source . --remote origin
```

---

## STEP 5 — Push the code (~3 min)

```bash
git init
git add .
git commit -m "NetScan Pro v2.0.0: async engine, plugin registry, NVD intel, CI/CD"
git branch -M main
git remote add origin https://github.com/<your-username>/netscan-pro.git
git push -u origin main
```

If GitHub asks for credentials, use a **Personal Access Token** (Settings →
Developer settings → Personal access tokens → `repo` scope) as your password,
or sign in via the GitHub CLI.

---

## STEP 6 — Replace the placeholders (~3 min)

Before anyone sees it, personalize:

1. In `README.md` and `pyproject.toml`: replace `<your-username>` and
   `Your Name` / `you@example.com` with your real details.
2. In `LICENSE`: replace `<your-name>` with your name.
3. (Bonus points) Take a screenshot of the HTML report or terminal output,
   put it in a `docs/` folder, and add it near the top of the README —
   repos with visuals get far more attention.

Commit and push again:
```bash
git add . && git commit -m "Personalize repo metadata, add screenshots"
git push
```

---

## STEP 7 — Watch CI go green (~5 min, automatic)

1. Open your repo → **Actions** tab.
2. You'll see the "CI" workflow running: ruff → mypy → pytest (x4 Python versions).
3. Wait for the green checkmark. This badge now works in your README.

If something fails, click the failing job — the error message tells you exactly
what to fix. Fix it locally, commit, push; CI re-runs automatically.

---

## STEP 8 — Final touches (~2 min)

- **Topics/tags**: on the repo page click the ⚙ next to "About", add tags:
  `python`, `security`, `network-scanner`, `asyncio`, `port-scanner`, `nvd`
- **Pin it**: on your GitHub profile, click "Customize pins" and pin netscan-pro
  to the top.
- **Codecov** (optional): sign in at https://codecov.io with GitHub, add the
  repo, copy the upload token into a GitHub secret named `CODECOV_TOKEN` —
  the coverage badge in the README will light up.

---

## STEP 9 — Interview-day checklist

- [ ] Can run `pytest` and explain ANY test
- [ ] Can demo: `netscan -t scanme.nmap.org -p 1-512`
- [ ] Can explain the 5 "Design decisions" from the README, especially:
      asyncio vs threads (GIL), the engine registry, fail-soft NVD caching
- [ ] Can point at a green CI run and the coverage report
- [ ] Can say what you'd add next (UDP engine is already architected for it)

Good luck! 🚀

# First GitHub publication

The local repository is on `main`. Source and documentation can be staged for review; secrets and generated artifacts stay ignored. The project needs no GitHub Actions secrets for its tests.

## Token setup (HTTPS)

Create the empty repository first. Under GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens, generate a token with:

- Your account as resource owner.
- Only this repository selected.
- A short expiration, such as 7 days for this first push.
- Repository **Contents: Read and write** and **Workflows: Read and write** (this project includes `.github/workflows/test.yml`). Leave other optional permissions off; Metadata read access is automatic.

Treat the token as a password. Paste it only into Git's password prompt; never put it in a remote URL, shell command, source file, screenshot or chat. Use two-factor authentication on the GitHub account. See [GitHub's token guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).

## Review and commit

```sh
git status --short
git diff --cached --stat
python3 scripts/check_public_files.py
git diff --cached
```

Verify that only source, tests, configuration templates and documentation are staged. Check screenshots manually before adding them. Review your Git author identity (`git config user.name` and `git config user.email`); use your GitHub-provided noreply address if you do not want your personal email in public commits.

For a private commit email, copy your exact noreply address from GitHub Settings → Emails, then set it for this repository before committing:

```sh
git config --local user.email "YOUR_GITHUB_NOREPLY_ADDRESS"
```

```sh
git commit -m "Initial release of Ephemeral Mesh"
```

## Create the remote and push

On GitHub, create an empty repository called `ephemeral-mesh`. Do not generate another README, license or .gitignore there because this project already supplies its own files. Copy the repository URL from GitHub and replace the placeholder:

```sh
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
# On macOS, override other credential helpers and save credentials in Keychain.
git -c credential.helper= -c credential.helper=osxkeychain push -u origin main
```

At the prompts, enter your GitHub username and paste the token as the password (the terminal will not display it). If Keychain already has a valid credential, there may be no prompt. Do not use `credential.helper store`, which stores credentials in plaintext. On other systems, use an OS-backed credential manager or GitHub CLI.

If a remote called `origin` already exists, inspect `git remote -v` before changing it. Do not use force-push to solve an unexpected remote-history conflict.

After pushing, check the Actions tab. Local success is not evidence a GitHub Actions run has passed. Configure GitHub's private vulnerability reporting if available for the repository, then update the contact guidance in `SECURITY.md`. Add a short repository description, for example:

> Invitation-only encrypted chat with durable offline delivery, local identities, encrypted media, and a self-hosted FastAPI relay.

Suggested topics: `python`, `fastapi`, `websockets`, `sqlite`, `self-hosted`, `encrypted-chat`, `docker`.

Create a `v1.0.0` release/tag after reviewing CI results and the deployed version. Describe it as a portfolio application with documented security limits, not an independently audited secure messenger. Refer to `RELEASE_CHECKS.md` for validation evidence and its scope.

## README assets

`docs/assets/demo.gif` is the full 25-second demo at 1200 pixels wide and 10 frames per second. It is silent and approximately 1.4 MiB. `docs/assets/architecture.svg` is an editable system diagram. The original `demooo.mov` is ignored and stays local. Sampled video frames were reviewed; preview the complete animation before publishing because image contents are not covered by the text-based publication guard.

To regenerate the demo with FFmpeg installed:

```sh
# Generate an optimized palette and use it for the looping README animation.
ffmpeg -i demooo.mov -an -map_metadata -1 -filter_complex '[0:v]fps=10,scale=1200:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle' -loop 0 docs/assets/demo.gif -y
```

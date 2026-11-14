# Releasing SentryCove

One version tag publishes everything: the Python package (PyPI), the Node
package (npm), the .NET package (NuGet), a multi-arch container image (GitHub
Container Registry) and a GitHub release with the built files attached.

No passwords or API tokens are stored in this repository. PyPI, npm and NuGet
each *trust this repository's release workflow directly* ("trusted
publishing"): at release time GitHub proves to the registry which workflow is
running, and the registry issues a credential that lasts minutes.

## One-time setup

Each registry stays switched off until you set its repository variable, so
you can enable them one at a time.

**Where to set a repository variable.** On GitHub (not on PyPI, npm or NuGet):

1. Open <https://github.com/XSiddhSaraf/sentrycove/settings/variables/actions>
   — or, from the repository page: **Settings** → **Secrets and variables** →
   **Actions** → the **Variables** tab.
2. Click **New repository variable**.
3. Enter the name (for example `PUBLISH_PYPI`) and the value `true`, then click
   **Add variable**.

To switch a registry off again, delete the variable or change its value.

Use these values wherever a registry asks which workflow to trust:

| Field | Value |
|---|---|
| Owner / organisation | `XSiddhSaraf` |
| Repository | `sentrycove` |
| Workflow file | `release.yml` |
| Environment | `pypi`, `npm` or `nuget` (one per registry, as below) |

### PyPI

1. Create an account at <https://pypi.org> and turn on two-factor authentication.
2. Open **Account → Publishing** and add a *pending publisher* for GitHub:
   PyPI project name `sentrycove`, plus the table above with environment `pypi`.
3. Set the repository variable `PUBLISH_PYPI` to `true` on GitHub
   ([where to set it](#one-time-setup)).

The name `sentrycove` is not reserved until the first release is published, so
do not leave a long gap between steps 2 and the first release.

### npm

npm sets up trusted publishing on a package's own settings page, so the package
has to exist first. The very first version is therefore published by hand from
your computer; every later version is published by the release workflow.

**First version, by hand** (needs Node.js 22 or newer and git):

```bash
git clone https://github.com/XSiddhSaraf/sentrycove.git
cd sentrycove/clients/node
npm ci                          # install the build tools
npm login                       # opens npmjs.com in your browser; approve with 2FA
npm whoami                      # should print your npm user name
npm publish --access public     # builds the package, then uploads it (asks for 2FA again)
```

Check that <https://www.npmjs.com/package/sentrycove> shows the new version.

**Later versions, automatically.** Do this shortly before your *next* release —
npm drops a trusted-publisher entry that has not published within two days:

1. Open <https://www.npmjs.com/package/sentrycove/access> and find **Trusted Publisher**.
2. Choose **GitHub Actions** and enter the table above with environment `npm`.
3. Set the repository variable `PUBLISH_NPM` to `true` on GitHub
   ([where to set it](#one-time-setup)).

If a release tag is pushed for a version that is already on npm (such as the
one you published by hand), the workflow notices and skips npm instead of failing.

### NuGet

1. Create an account at <https://www.nuget.org>.
2. Click your user name → **Trusted Publishing** → add a policy with yourself
   as owner and the table above with environment `nuget`.
3. Add a repository *secret* named `NUGET_USER` containing your nuget.org user
   name (the profile name, not your email address). Secrets live next to the
   variables: same page, **Secrets** tab → **New repository secret**.
4. Set the repository variable `PUBLISH_NUGET` to `true` on GitHub
   ([where to set it](#one-time-setup)).

### Container image

Nothing to set up: the image is pushed to
`ghcr.io/xsiddhsaraf/sentrycove` with the workflow's own GitHub token. GitHub
creates container packages as **private**, so after the first release open the
package's settings page and change its visibility to **Public**.

### Recommended hardening

- **Settings → Environments**: open `pypi`, `npm` and `nuget` (GitHub creates
  them on first use, or create them yourself beforehand) and add yourself as a
  *required reviewer*. Publishing then waits for your click.
- **Settings → Rules → Rulesets**: restrict who may create tags matching `v*`.
- Enable **private vulnerability reporting** under Settings → Security.

## Cutting a release

1. Set the new version in all four places and add a `CHANGELOG.md` entry:
   - `pyproject.toml` and `src/sentrycove/__init__.py`
   - `clients/node/package.json` (then run `npm install` there to refresh the lock file)
   - `clients/dotnet/src/SentryCove.AspNetCore/SentryCove.AspNetCore.csproj`

   `python scripts/check_versions.py` confirms they agree.
2. Merge to `main` and wait for CI to pass.
3. Tag and push:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
4. Watch **Actions → Release**. The workflow first checks that the tag matches
   the package versions, then runs the complete test suite, and only then publishes.

After the first release, delete the "not yet published" note at the top of `README.md`.

## Things to know

- **A published version is permanent.** PyPI, npm and NuGet never let a version
  number be reused, even after deletion. If a release is wrong, fix it and
  publish the next patch version.
- Only plain `vX.Y.Z` tags trigger a release; there is no pre-release channel yet.
- If one registry fails, the others are unaffected. Fix the cause and use
  **Re-run failed jobs** — but only if that registry has not already accepted the version.

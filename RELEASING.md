# Releasing SignalMoat

One version tag publishes everything: the Python package (PyPI), the Node
package (npm), the .NET package (NuGet), a multi-arch container image (GitHub
Container Registry) and a GitHub release with the built files attached.

No passwords or API tokens are stored in this repository. PyPI, npm and NuGet
each *trust this repository's release workflow directly* ("trusted
publishing"): at release time GitHub proves to the registry which workflow is
running, and the registry issues a credential that lasts minutes.

## Moving from SentryCove to SignalMoat (do once, in this order)

The project was renamed in 0.3.0, so every registry needs a fresh entry under
the new name. Registries check the *repository's* name, so rename it first.

1. **Merge** the rename pull request.
2. **Rename the repository**: GitHub → **Settings → General → Repository name**
   → `signalmoat` → **Rename**. GitHub redirects the old address, so existing
   links and clones keep working.
3. **PyPI**: add a pending publisher for the project name `signalmoat`
   ([PyPI](#pypi) below). The old `sentrycove` publisher can be removed.
4. **npm**: publish `signalmoat` 0.3.0 by hand ([npm](#npm) below).
5. **NuGet**: open your Trusted Publishing policy and change the repository to
   `signalmoat` and the glob pattern to `SignalMoat.AspNetCore` (or delete the
   policy and add a new one — [NuGet](#nuget) below).
6. **Release** 0.3.0 ([Cutting a release](#cutting-a-release)).
7. **Retire the old names** so nobody installs them by mistake:
   - npm: `npm deprecate sentrycove "Renamed to signalmoat: npm install signalmoat"`
   - PyPI: open the `sentrycove` project → **Settings** → **Archive project**.
   - Container image: delete the old `sentrycove` package from your GitHub
     packages page, or leave it; it receives no new tags.

## One-time setup

Each registry stays switched off until you set its repository variable, so
you can enable them one at a time.

**Where to set a repository variable.** On GitHub (not on PyPI, npm or NuGet):

1. Open <https://github.com/XSiddhSaraf/signalmoat/settings/variables/actions>
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
| Repository | `signalmoat` |
| Workflow file | `release.yml` |
| Environment | `pypi`, `npm` or `nuget` (one per registry, as below) |

### PyPI

1. Create an account at <https://pypi.org> and turn on two-factor authentication.
2. Open **Account → Publishing** and add a *pending publisher* for GitHub:
   PyPI project name `signalmoat`, plus the table above with environment `pypi`.
3. Set the repository variable `PUBLISH_PYPI` to `true` on GitHub
   ([where to set it](#one-time-setup)).

The name `signalmoat` is not reserved until the first release is published, so
do not leave a long gap between steps 2 and the first release.

### npm

npm sets up trusted publishing on a package's own settings page, so the package
has to exist first. The very first version is therefore published by hand from
your computer; every later version is published by the release workflow.

**First version, by hand** (needs Node.js 22 or newer and git):

```bash
git clone https://github.com/XSiddhSaraf/signalmoat.git
cd signalmoat/clients/node
npm ci                          # install the build tools
npm login                       # opens npmjs.com in your browser; approve with 2FA
npm whoami                      # should print your npm user name
npm publish --access public     # builds the package, then uploads it (asks for 2FA again)
```

Check that <https://www.npmjs.com/package/signalmoat> shows the new version.

**Later versions, automatically.** Do this shortly before your *next* release —
npm drops a trusted-publisher entry that has not published within two days:

1. Sign in to npmjs.com and open <https://www.npmjs.com/package/signalmoat/access>
   (from the package page: the **Settings** tab). This page only exists once
   the first version has been published. npm may ask for your 2FA code.
2. Scroll to the **Trusted Publisher** section and click **GitHub Actions**.
3. Fill in the form exactly like this:

   | Form field | What to type |
   |---|---|
   | Organization or user | `XSiddhSaraf` |
   | Repository | `signalmoat` |
   | Workflow filename | `release.yml` (the file name only, with `.yml`, no folder) |
   | Environment name | `npm` |

   If the form has an **Allowed actions** choice, tick **npm publish** — that
   is the command the release workflow runs.
4. Click the button that saves the publisher (**Set up connection**) and
   confirm with 2FA if asked. The section should now list
   `XSiddhSaraf/signalmoat` with `release.yml`.
5. Set the repository variable `PUBLISH_NPM` to `true` on GitHub
   ([where to set it](#one-time-setup)).

npm does not check these values when you save them; a typo only shows up as a
failed publish. An entry cannot be edited afterwards — delete it and add it
again.

If a release tag is pushed for a version that is already on npm (such as the
one you published by hand), the workflow notices and skips npm instead of failing.

### NuGet

1. Create an account at <https://www.nuget.org>.
2. Click your user name → **Trusted Publishing** → add a policy with yourself
   as owner and the table above with environment `nuget`.
   - **Scope:** allow pushing **new packages and new versions** — the package
     does not exist on nuget.org yet, so the first release creates it.
   - **Glob pattern:** type `SignalMoat.AspNetCore`. The list of existing
     packages is empty until the first release, which is why the form says
     "At least one valid glob pattern or package must be specified" until you
     type one. (`SignalMoat.*` also works and would cover future SignalMoat
     packages, at the cost of a broader permission.)
3. Add a repository *secret* named `NUGET_USER` containing your nuget.org user
   name (the profile name, not your email address). Secrets live next to the
   variables: same page, **Secrets** tab → **New repository secret**.
4. Set the repository variable `PUBLISH_NUGET` to `true` on GitHub
   ([where to set it](#one-time-setup)).

### Container image

Nothing to set up: the image is pushed to
`ghcr.io/xsiddhsaraf/signalmoat` with the workflow's own GitHub token. GitHub
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
   - `pyproject.toml` and `src/signalmoat/__init__.py`
   - `clients/node/package.json` (then run `npm install` there to refresh the lock file)
   - `clients/dotnet/src/SignalMoat.AspNetCore/SignalMoat.AspNetCore.csproj`

   `python scripts/check_versions.py` confirms they agree.
2. Merge to `main` and wait for CI to pass.
3. Create the tag `vX.Y.Z` (for example `v0.3.0`) on `main`, either way:
   - **On github.com:** **Releases → Draft a new release → Choose a tag** → type
     the tag → **Create new tag on publish** → target `main` → **Publish release**.
   - **From a terminal:**
     ```bash
     git pull
     git tag v0.3.0
     git push origin v0.3.0
     ```
4. Watch **Actions → Release**. The workflow first checks that the tag matches
   the package versions, then runs the complete test suite, and only then publishes.

## Things to know

- **A published version is permanent.** PyPI, npm and NuGet never let a version
  number be reused, even after deletion. If a release is wrong, fix it and
  publish the next patch version.
- Only plain `vX.Y.Z` tags trigger a release; there is no pre-release channel yet.
- If one registry fails, the others are unaffected. Fix the cause and use
  **Re-run failed jobs**. **Re-run all jobs** is safe too: each registry skips a
  version it already has.
- A registry that was switched off when the release ran is *not* picked up by
  **Re-run failed jobs**; switch it on and use **Re-run all jobs**.
- The first container push for a brand-new image can be refused for one
  architecture while the other creates the image. Re-run the failed job.

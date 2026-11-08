# Trapline

> **Trapline — set traps for vulnerable code: from CVE to opengrep/semgrep rule.**

A trapline is the route of traps a trapper sets and checks regularly. Here, each rule is a trap for one kind of vulnerable code, and the rule set runs on every change.

Trapline is a web editor and CLI for writing, testing and maintaining [opengrep](https://github.com/opengrep/opengrep) and [semgrep](https://semgrep.dev) rules, plus a generator that turns a CVE into rule drafts. It runs on its own, as a Rack app, or mounted inside a Rails app. Its only requirements are Ruby and the engine binary.

- **Web editor.** Validates the YAML as you type, keeps a metadata form in sync with it, and runs the rule against test code. Findings are highlighted in the code. You mark which lines must or must not match by clicking the margin or accepting results; you don't write annotation comments by hand.
- **CVE generator.** Looks the CVE up in NVD and OSV (CWE, CVSS, affected packages and versions) and proposes drafts: a template for the vulnerability class, a check for vulnerable runtime images, a rule that finds usage of the affected package, and a taint skeleton. The metadata is filled in for you.
- **Plain files.** Each rule is saved as `name.yaml` next to its test file `name.<ext>`. This is the layout `opengrep --test` and `semgrep --test` expect, so the folder works without Trapline.
- **CI-friendly.** `trapline test` runs every rule against its test file and exits non-zero on failure.

---

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [The web editor](#the-web-editor)
- [Generating rules from a CVE](#generating-rules-from-a-cve)
- [Command line](#command-line)
- [Rules folder and test annotations](#rules-folder-and-test-annotations)
- [Using the rules in CI](#using-the-rules-in-ci)
- [Rails integration](#rails-integration)
- [Running on any Rack server](#running-on-any-rack-server)
- [Configuration reference](#configuration-reference)
- [Ruby API](#ruby-api)
- [Security](#security)
- [Development](#development)
- [License](#license)

---

## Requirements

- **Ruby 3.3 or later.**
- **An engine: opengrep or semgrep.** Trapline looks for `opengrep` first, then `semgrep`, on your `PATH`. Without an engine, the editor still opens and validates rule structure, but it cannot run rules.
- **Network access (optional)** to `services.nvd.nist.gov` and `api.osv.dev`, for the CVE generator. Without it, you can type the CVE data in by hand.

There are no required gem dependencies. If `rackup` and `puma` (or `webrick`) are installed, `trapline server` uses them; otherwise it uses a small built-in HTTP server that is enough for local use.

## Installation

### 1. Install the gem

From RubyGems:

```bash
gem install trapline
```

Or add it to a project's `Gemfile`:

```ruby
gem "trapline"
```

Or build it from source:

```bash
git clone https://github.com/JAugusto42/trapline.git
cd trapline
gem build trapline.gemspec
gem install ./trapline-*.gem
```

### 2. Install an engine

opengrep (recommended):

```bash
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
```

The installer puts the binary in `~/.opengrep/cli/latest/`. Make sure that directory is on your `PATH`, or point Trapline to the binary with `--engine-bin` or `TRAPLINE_ENGINE`.

Or semgrep:

```bash
pip install semgrep      # or: brew install semgrep
```

### 3. Check the setup

```bash
trapline version
# trapline 0.1.1
# engine: opengrep 1.33.1 (/Users/you/.opengrep/cli/latest/opengrep)
```

## Quick start

```bash
mkdir rules
trapline server -r ./rules
```

Open <http://127.0.0.1:9292>. Then either:

- click **New rule**, pick a rule type and a language, and edit the example; or
- click **Generate from CVE**, enter an id such as `CVE-2021-44228`, pick a draft and click **Open in editor**.

Click **Run** (or press Ctrl/Cmd+Enter) to run the rule against the test code. Click **Save** (Ctrl/Cmd+S) to write it to `./rules`.

## The web editor

The screen has three columns:

| Column | What it holds |
|---|---|
| **Left** | Your saved rules (with a filter by id, CVE or CWE), **New rule** and **Generate from CVE** |
| **Middle** | **Rule details**, a form for id, severity, languages, message, CWE, CVE, confidence and references, kept in sync with the **YAML** editor below it. Validation issues appear under the YAML as you type. |
| **Right** | **Test code**: an example file the rule runs against, with the run result on top and the per-line results below |

### Writing test code

The test code is an example file with code the rule **must** flag and code it **must not** flag. Trapline checks each run against those expectations:

- **Mark lines from the margin.** Click the margin next to a line to cycle its expectation: **must match** → **must not match** → **no expectation**.
- **Accept results.** After a run, each flagged line that has no expectation yet shows two buttons. **Expected** keeps it as a test; **False positive** records that the rule should not match there. **Accept all as expected** does this for every new finding at once.
- **Fix failing expectations.** A line expected to match that doesn't gets a **Remove** button. A line expected not to match that does gets an **Expect it** button.

A typical loop is: paste a vulnerable snippet and a fixed one, run, accept what is right, mark what is wrong, then refine the rule until everything passes.

The expectations are stored as ordinary `ruleid:` / `ok:` comments in the test file, so the file stays in the `--test` format that opengrep and semgrep read. Trapline writes and removes them for you, and if you rename the rule's id, it rewrites them too. In the editor each comment is drawn as a compact badge (**must match**, **must not match**, or a *todo* variant) on its own line, so line numbers stay the same as in the file. Click a badge to edit the comment by hand, or tick **Show comments** to see them all as text. See [Rules folder and test annotations](#rules-folder-and-test-annotations) for the format.

### Running

- **Run** runs the rule once. With **Run on edit** checked, it also runs after each pause in typing.
- The card above the test code shows the outcome:
  - **green**: all expectations met;
  - **red**: an expectation failed, or the engine reported an error, such as an invalid pattern;
  - **blue**: the code has no expectations yet.
- A run started with the button or the shortcut also shows a notification.
- Markers in the margin show the result for each line: ✓ passed, ✕ failed, ! flagged with no expectation.

### Saving and downloading

- **Save** (Ctrl/Cmd+S) writes the rule and its test code to the rules folder. The file name defaults to the last part of the rule id; for example, `php.lang.security.cve-2026-109618-custom` is saved as `cve-2026-109618-custom.yaml`.
- **Download** saves the YAML through the browser.
- **Delete** removes a saved rule and its test file.
- In read-only mode (`--read-only`, or the Rails default outside development), saving and deleting are disabled. Validating and running still work.

### Keyboard shortcuts

| Shortcut | Action |
|---|---|
| Ctrl/Cmd + Enter | Run |
| Ctrl/Cmd + S | Save |
| Tab / Shift + Tab | Indent / outdent |

## Generating rules from a CVE

In the editor, click **Generate from CVE**, enter a `CVE-…` or `GHSA-…` id, optionally choose a **Language**, and click **Search**.

Trapline shows:

- a summary of the advisory: severity, CVSS, CWEs, aliases and sources;
- **notes** that explain what it inferred and what needs review;
- a list of **drafts**.

Pick a draft and click **Open in editor**.

If the machine has no network access, open **No network access? Enter the data manually** and fill in the CWE, ecosystem, package, fixed version and description.

From the command line:

```bash
trapline cve CVE-2021-44228                  # lists the drafts and prints the first
trapline cve CVE-2021-44228 --lang java      # prefer one language
trapline cve CVE-2021-44228 --pick 2 --save  # save the 2nd draft to the rules folder
trapline cve --osv-json advisory.json        # offline: use a downloaded OSV record
```

### Draft types

| Draft | When it appears | What it does |
|---|---|---|
| **Vulnerability class** (e.g. *SQL injection (CWE-89)*) | A bundled template matches the CWE | Taint or pattern rule for that class, in the chosen language, with an annotated example |
| **Vulnerable runtime version** | The CVE affects PHP, Python, Node.js, Ruby, Go or .NET itself and NVD lists version ranges (for Go, OSV's `stdlib` ranges also count) | Regex rule that flags references to the official image (`FROM php:8.2.34-fpm`, `image: php:8.2.34` in Compose, Kubernetes or CI files, Helm `repository:` + `tag:`, `docker run`) when the tag falls in an affected range. For .NET, `mcr.microsoft.com/dotnet/runtime` and `aspnet`. The notes recommend an image scanner (Trivy, Grype, osv-scanner) for built images and OS packages |
| **Usage of package** | OSV lists affected packages in RubyGems, PyPI, npm, Maven or Go | Finds `require` / `import` / `gem "…"` of the package; the message names the fixed version |
| **Taint skeleton** | Always | Source / sanitizer / sink skeleton with the CVE metadata filled in, for writing the rule by hand |

### How the generator decides

- **Vulnerability class.** If the CVE reports a CWE that has a template, Trapline uses it. Aliases are mapped, so CWE-77 uses the CWE-78 template and CWE-564 uses CWE-89. When several CWEs match, the one that best fits the description comes first.

  Trapline only guesses from keywords in the description ("SQL injection", "path traversal"…) when the CVE reports no CWE or only a generic one, such as CWE-20. It never treats "remote code execution" as a class: that is an impact, shared by memory corruption, deserialization and command injection.
- **Language.** The one you pick. Otherwise, the ecosystem of the affected packages. Otherwise, the affected runtime or framework named in the NVD CPE data (e.g. `php:php` → PHP, `djangoproject:django` → Python). As a last resort, Ruby, and a note says so. When a CVE affects several languages, a note lists them so you can regenerate for another one.
- **Severity.** Copied from the CVE: CRITICAL, HIGH, MEDIUM or LOW. MODERATE and unknown map to MEDIUM. opengrep and current semgrep accept this scale; semgrep releases from before 2024 only accept ERROR / WARNING / INFO.
- **Rule id.** Follows the registry convention `<language>.<framework or "lang">.security.<name>`, for example `java.lang.security.cve-2021-44228-expression-language-jndi-lookup-injection` or `regex.php.security.cve-2026-109618-vulnerable-php-image`.
- **Memory-safety CVEs** (use-after-free, buffer overflow…) live in native code, so no rule over application code can find them. The notes say so, and the runtime-version draft is usually the most useful one.

Every draft is a starting point. Read the notes, then refine the rule and its test code before relying on it.

### Bundled templates

```bash
trapline templates
```

| CWE | Class | Languages |
|---|---|---|
| 22 | Path traversal | ruby, python, javascript, java, go |
| 78 | OS command injection | ruby, python, javascript, java, go |
| 79 | Cross-site scripting (XSS) | ruby, python, javascript, java, go |
| 89 | SQL injection | ruby, python, javascript, java, go |
| 94 | Code injection | ruby, python, javascript, java |
| 327 | Weak cryptography | ruby, python, javascript, java, go |
| 502 | Insecure deserialization | ruby, python, javascript, java |
| 601 | Open redirect | ruby, python, javascript, java, go |
| 611 | XML external entities (XXE) | java, python, ruby |
| 798 | Hard-coded credentials | ruby, python, javascript, java, go |
| 917 | Expression language / JNDI lookup injection | java |
| 918 | Server-side request forgery (SSRF) | ruby, python, javascript, java, go |

The **New rule** dialog also offers four starting points, each with example test code: a simple pattern, a combination with `pattern-not`, data flow (taint) and a regular expression.

## Command line

```
trapline <command> [options]
```

Global options, accepted by every command:

| Option | Meaning |
|---|---|
| `-r, --rules DIR` | Rules folder (default: `./rules`, or `$TRAPLINE_RULES_PATH`) |
| `--engine-bin BIN` | Engine to use: `opengrep`, `semgrep` or a path |

### `trapline server`

Opens the web editor.

```bash
trapline server -r ./rules                          # http://127.0.0.1:9292
trapline server -p 8080                             # other port
trapline server --host 0.0.0.0 --basic-auth admin:secret
trapline server --read-only                         # validate and run only
trapline server --offline                           # no NVD/OSV requests
```

| Option | Meaning |
|---|---|
| `-p, --port PORT` | Port (default 9292) |
| `-b, --host HOST` | Interface (default `127.0.0.1`) |
| `--basic-auth USER:PASS` | Require HTTP Basic authentication |
| `--read-only` | Disable saving and deleting |
| `--offline` | Disable network lookups; CVE data must be typed in |

### `trapline validate FILE...`

Checks rule structure: required keys, patterns, languages, severity, metavariables and recommended metadata.

```bash
trapline validate rules/*.yaml
trapline validate rules/*.yaml --engine   # also ask opengrep/semgrep to load the rule
trapline validate rules/sqli.yaml --json
```

Exits with 1 if any file has errors.

### `trapline test [DIR]`

Runs every rule in the rules folder against its test file and checks the annotations. Use it in CI.

```bash
trapline test -r rules
# ok    sql-injection (4/4)
# FAIL  open-redirect (2/3)
#       false negative: expected a finding on line 12
#
# 2 rules, 1 with problems
```

Exits with 1 if any rule fails or errors. Rules without a test file are reported as `no test`, and test files without annotations as `no annotations`. Neither of those fails the run.

### `trapline run RULE TARGET`

Runs one rule against one source file. The language comes from the file extension.

```bash
trapline run rules/sqli.yaml app/models/user.rb
trapline run rules/sqli.yaml app/models/user.rb --json
```

### `trapline cve ID`

See [Generating rules from a CVE](#generating-rules-from-a-cve).

| Option | Meaning |
|---|---|
| `-l, --lang LANG` | Preferred language |
| `--pick N` | Choose the Nth draft (default 1) |
| `--save` | Save the chosen draft to the rules folder instead of printing it |
| `--osv-json FILE` | Read a downloaded OSV record instead of querying the network |

### `trapline templates` and `trapline version`

`templates` lists the bundled CWE templates. `version` shows the Trapline version and the detected engine.

## Rules folder and test annotations

Trapline stores rules in the `--test` layout used by opengrep and semgrep: one YAML file per rule, with a test file of the same name next to it.

```
rules/
  sql-injection.yaml        # the rule
  sql-injection.rb          # its test code
  web/
    open-redirect.yaml      # subfolders are allowed
    open-redirect.py
```

The test file marks the expected results with comments on the line **above** the code. The comment can also go at the end of the line itself.

```ruby
# ruleid: ruby.rails.security.sql-injection
User.where("name = '#{params[:name]}'")

# ok: ruby.rails.security.sql-injection
User.where(name: params[:name])
```

| Annotation | Meaning |
|---|---|
| `ruleid: <id>` | The next line **must** produce a finding |
| `ok: <id>` | The next line **must not** produce a finding |
| `todoruleid: <id>` | Known false negative: reported, but does not fail |
| `todook: <id>` | Known false positive: reported, but does not fail |

Additional rules:

- Several ids can share a comment: `# ruleid: rule-a, rule-b`.
- As in `--test`, every id in a `ruleid`, `ok` or `todoruleid` comment must be a rule of the file; otherwise the annotation fails. `todook` is exempt.
- A finding on a line with no annotation counts as a failure ("unexpected match on line N (the line is not marked as expected)").
- An annotation with no code below it, such as one followed by a blank line or at the end of the file, counts as a failure. Otherwise it would pass without testing anything.
- The comment prefix follows the language: `#` for Ruby, Python, YAML and Dockerfile; `//` for JavaScript, Java, Go, PHP and the C family.

Because the layout is the standard one, you can also run `opengrep --test rules/` or `semgrep --test rules/` directly.

## Using the rules in CI

Two separate jobs are useful:

1. **Test the rules** against their test files, with `trapline test`.
2. **Scan your code** with the rules, using the engine directly.

Example for GitHub Actions:

```yaml
name: security-rules
on: [pull_request]

jobs:
  rules:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ruby/setup-ruby@v1
        with: { ruby-version: "3.3" }
      - name: Install opengrep
        run: |
          curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
          echo "$HOME/.opengrep/cli/latest" >> "$GITHUB_PATH"
      - run: gem install trapline
      - name: Test the rules
        run: trapline test -r security/semgrep
      - name: Scan the code
        run: opengrep scan --config security/semgrep --exclude security/semgrep --error .
```

Keep the `--exclude` on the scan: the rules folder contains the test files, which are vulnerable on purpose.

## Rails integration

Add the gem and run the installer:

```ruby
# Gemfile
gem "trapline"
```

```bash
bundle install
bin/rails generate trapline:install                  # mounts the editor at /trapline
bin/rails generate trapline:install --path /admin/rules
```

The installer:

- adds the route `mount Trapline::Web::App.new, at: "/trapline"` to `config/routes.rb`;
- creates `config/initializers/trapline.rb`;
- creates the rules folder `security/semgrep/`.

The generated initializer:

```ruby
Trapline.configure do |config|
  config.rules_path = Rails.root.join("security", "semgrep").to_s

  # Who can open the editor. Receives the Rack env; return true to allow access.
  #   config.authorize = ->(env) { env["warden"]&.user&.admin? }                    # Devise/Warden
  #   config.authorize = [ENV.fetch("TRAPLINE_USER"), ENV.fetch("TRAPLINE_PASSWORD")]  # HTTP Basic
  config.authorize = ->(_env) { Rails.env.development? }

  # Read-only outside development (the editor still validates and runs rules).
  config.read_only = !Rails.env.development?
end
```

The defaults:

- **Access.** The editor is only reachable in development. To use it elsewhere, change `authorize`.
- **Read-only.** Outside development the editor is read-only, even if you remove the line above: the Railtie sets it. Set `config.read_only = false` in the initializer to allow writes.
- **Rules folder.** `security/semgrep`, unless `TRAPLINE_RULES_PATH` is set.

> **Note.** If you mount the editor without the initializer, `authorize` is `nil` and the editor is open to anyone who can reach the route. Always set `authorize`.

Rake tasks, for CI:

```bash
bin/rails trapline:test       # run every rule against its test file
bin/rails trapline:validate   # validate the structure of every rule
```

You can also set options from `config/application.rb` or an environment file through `config.trapline`:

```ruby
config.trapline.engine_binary = "/usr/local/bin/opengrep"
config.trapline.allow_network = false
```

## Running on any Rack server

Copy `config.ru.example` (shipped with the gem) to `config.ru`:

```ruby
require "trapline"

credentials = %w[TRAPLINE_USER TRAPLINE_PASSWORD].map do |name|
  ENV.fetch(name) { abort "config.ru: set TRAPLINE_USER and TRAPLINE_PASSWORD (HTTP Basic credentials)" }
end

Trapline.configure do |c|
  c.rules_path = ENV.fetch("TRAPLINE_RULES_PATH", File.expand_path("rules", __dir__))
  c.authorize = credentials
end

run Trapline::Web::App.new
```

```bash
TRAPLINE_USER=admin TRAPLINE_PASSWORD=change-me bundle exec puma
```

Your `Gemfile` needs `gem "trapline"` and a server such as `gem "puma"`.

## Configuration reference

### Ruby options

Set them with `Trapline.configure { |c| ... }`:

| Option | Default | Meaning |
|---|---|---|
| `rules_path` | `./rules` | Folder where rules and their tests are stored |
| `engine_binary` | auto (`opengrep`, then `semgrep`) | Engine name or absolute path |
| `engine_timeout` | `60` | Seconds allowed for a single engine run |
| `authorize` | `nil` (no check) | Who can use the web editor: a callable receiving the Rack env and returning true/false, or a `[user, password]` pair for HTTP Basic. Any other value denies access. |
| `read_only` | `false` (Rails: `true` outside development) | Disable saving and deleting in the editor |
| `allow_network` | `true` | Allow NVD/OSV lookups |
| `cve_timeout` | `30` | Seconds allowed for a whole CVE lookup (several NVD/OSV requests); requests left over are skipped and a note says the data may be incomplete |
| `nvd_api_key` | `nil` | NVD API key, which raises the NVD rate limit |

### Environment variables

| Variable | Effect |
|---|---|
| `TRAPLINE_RULES_PATH` | Rules folder |
| `TRAPLINE_ENGINE` | Engine binary (name or path) |
| `TRAPLINE_ENGINE_TIMEOUT` | Engine timeout in seconds |
| `TRAPLINE_CVE_TIMEOUT` | CVE lookup time limit in seconds |
| `TRAPLINE_OFFLINE=1` | Disable NVD/OSV lookups |
| `NVD_API_KEY` | NVD API key ([request one](https://nvd.nist.gov/developers/request-an-api-key)) |
| `TRAPLINE_BUILTIN_SERVER=1` | Use the built-in HTTP server even when puma/webrick are installed |
| `TRAPLINE_LOG=1` | Log requests (built-in server) |

## Ruby API

```ruby
require "trapline"

# Validate
result = Trapline.validate(File.read("rules/sqli.yaml"), engine: true)
result.valid?    # => true / false
result.issues    # => [#<Issue level="warning" path="rules[0].metadata" message="...">]

# Run with annotations
run = Trapline.engine.run(File.read("rules/sqli.yaml"), code: File.read("rules/sqli.rb"), language: "ruby")
run.findings     # => [#<Finding rule_id="..." line=4 code="...">]
run.annotations  # => { total: 5, passed: 5, failed: 0, results: [...] }

# Generate from a CVE
draft = Trapline.generate_from_cve("CVE-2021-44228")
draft[:notes]                      # what was inferred
draft[:candidates].first[:yaml]
draft[:candidates].first[:test_code]

# Generate from data typed in by hand (no network)
Trapline::Generator.new.analyze({
  id: "CVE-2099-0001", cwes: "CWE-78", severity: "HIGH",
  description: "OS command injection in the host parameter",
  packages: [{ ecosystem: "npm", name: "ping-lib", fixed: "2.0.0" }]
})

# Rules on disk
store = Trapline.store             # uses config.rules_path
store.list                         # => [{ slug: "sql-injection", id: "...", ... }]
store.write("sql-injection", yaml, test_code: code, language: "ruby")
```

## Security

- The standalone server listens on `127.0.0.1` by default. Bind it to another interface only together with `--basic-auth` or `authorize`.
- **The editor runs the engine on code the user types.** Only give access to people you trust.
- `authorize` fails closed: a value that is neither a callable nor a `[user, password]` pair denies access.
- Requests that change state require the `X-Trapline: 1` header, which protects against CSRF.
- Rule names are checked against path traversal before touching the disk.
- The engine runs in a temporary directory with metrics and version checks disabled. Temporary paths are removed from error messages.

## Development

```bash
bundle install
bundle exec rake test                    # tests that need the engine are skipped without one
ruby -Ilib exe/trapline server -r tmp/rules
```

To run the server with puma inside this repository, enable the optional group first: `bundle config set --local with server && bundle install`.

Layout:

```
lib/trapline/
  cli.rb           command-line interface
  configuration.rb options and environment variables
  rule.rb          parsing and dumping readable YAML
  validator.rb     structural validation (+ optional validation by the engine)
  engine.rb        opengrep/semgrep wrapper and annotation checking
  store.rb         rules on disk in the --test layout
  suite.rb         runs every rule against its test file
  cve/             NVD 2.0 and OSV clients and the normalized record
  templates.rb     template library (CWE templates, starters, package usage)
  templates/cwe/   one YAML file per CWE: rule body and annotated test code per language
  runtime.rb       runtime-version (container image) rules from NVD version ranges
  generator.rb     CVE -> rule drafts
  web/app.rb       Rack app: JSON API and editor
  web/server.rb    standalone server (rackup when available, built-in otherwise)
  web/assets/      editor: plain JavaScript, with CodeMirror 5 and fonts bundled (works offline)
  railtie.rb       Rails integration
lib/generators/    rails generate trapline:install
lib/tasks/         rake trapline:test / trapline:validate
```

To add a template, create `lib/trapline/templates/cwe/cwe-<n>.yml` with the rule body and annotated test code for each language. `test/test_templates.rb` runs every template through the engine, so the new one is covered automatically.

### Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`, which checks that the tag matches `Trapline::VERSION`, runs the tests with opengrep, publishes the gem to RubyGems and creates a GitHub release with the `.gem` attached:

```bash
# bump lib/trapline/version.rb, commit, then:
git tag v0.1.0
git push origin v0.1.0
```

Publishing uses [RubyGems trusted publishing](https://guides.rubygems.org/trusted-publishing/), so no API key is stored in the repository. It must be set up once on rubygems.org: as a pending trusted publisher for the first release, with repository `JAugusto42/trapline`, workflow `release.yml` and environment `release`. A pending publisher expires after about 12 hours, so create it right before pushing the first tag. The workflow names the owning account (`RUBYGEMS_OWNER_ID`) when it exchanges the GitHub token, as RubyGems requires for a new gem's first push.

## License

MIT. See [LICENSE](LICENSE). CodeMirror and the bundled fonts keep their own licenses, listed in `lib/trapline/web/assets/THIRD_PARTY_LICENSES.txt`.

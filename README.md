![Splunkbase Downloads](https://img.shields.io/endpoint?url=https%3A%2F%2Fsplunkbasebadge.livehybrid.com%2Fv1%2Fdownloads%2F6731)
![Cloud Compatible](https://img.shields.io/endpoint?logo=icloud&url=https%3A%2F%2Fsplunkbasebadge.livehybrid.com%2Fv1%2Fsplunkcloud%2F6731)
![Splunkbase Compatibility](https://img.shields.io/endpoint?url=https%3A%2F%2Fsplunkbasebadge.livehybrid.com%2Fv1%2Flatest_compat%2F6731)

# Binary File Declaration
File: lib/_cffi_backend.cpython-39-x86_64-linux-gnu.so
Source: https://pypi.org/project/cffi/
Note: This is a Python library (_cffi_backend) - https://pypi.org/project/cffi/
Binary Format: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=9e40250e5768f09e645abd0c41b7f943436b49d6, with debug_info, not stripped

File: lib/charset_normalizer/md.cpython-39-x86_64-linux-gnu.so
Source: https://pypi.org/project/charset-normalizer/
Note: This is a Python library (charset_normalizer) - https://pypi.org/project/charset-normalizer/
Binary Format: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=70e32f6b4c4800da2508b2effef36317496b3985, not stripped

File: lib/charset_normalizer/md__mypyc.cpython-39-x86_64-linux-gnu.so
Source: https://pypi.org/project/charset-normalizer/
Note: This is a Python library (charset_normalizer) - https://pypi.org/project/charset-normalizer/
Binary Format: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=4aa45ee0abeaa33f14209287f86c1c73ca4bb004, not stripped

File: lib/nacl/_sodium.abi3.so
Source: https://pypi.org/project/PyNaCl/
Note: This is a Python library (nacl) - https://pypi.org/project/PyNaCl/
Binary Format: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, BuildID[sha1]=ba8673191963843e13d796864213edd0413bcb8c, with debug_info, not stripped

File: lib/3rdparty/linux/aarch64/python39/_cffi_backend.cpython-39-aarch64-linux-gnu.so
Source: https://pypi.org/project/cffi/
Note: This is a Python library (_cffi_backend) - https://pypi.org/project/cffi/
Binary Format: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, BuildID[sha1]=46e3f96f284fe5d01bb612307a479ae684f09999, with debug_info, not stripped

File: lib/3rdparty/linux/aarch64/python39/nacl/_sodium.abi3.so
Source: https://pypi.org/project/PyNaCl/
Note: This is a Python library (nacl) - https://pypi.org/project/PyNaCl/
Binary Format: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, BuildID[sha1]=ddb7cc4bc4084dc1d7573bd9a5db11064fe18bda, with debug_info, not stripped

File: lib/3rdparty/linux/x86_64/python39/_cffi_backend.cpython-39-x86_64-linux-gnu.so
Source: https://pypi.org/project/cffi/
Note: This is a Python library (_cffi_backend) - https://pypi.org/project/cffi/
Binary Format: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=915369b7c7ab5119b66cf968649892624482e74f, with debug_info, not stripped

File: lib/3rdparty/linux/x86_64/python39/nacl/_sodium.abi3.so
Source: https://pypi.org/project/PyNaCl/
Note: This is a Python library (nacl) - https://pypi.org/project/PyNaCl/
Binary Format: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=901be8963015863f2543d6af6a9213d23a7f7466, with debug_info, not stripped

# Automated Testing

This app includes comprehensive automated testing infrastructure that integrates with 1Password for secret management, builds and deploys the app to Splunk Cloud, creates test accounts, executes token generation searches, and validates tokens across all supported destinations.

## Local development (Docker)

To test the app locally without Splunk Cloud (faster iteration):

1. **Start local Splunk** (builds the app, builds the image, starts containers; first run can take a few minutes):

   ```bash
   make local-dev
   ```

   This runs `make build`, `make docker-build`, then `docker-compose` with fixed ports:
   - **Web UI:** http://localhost:8000 (login: `admin` / `Chang3d!`)
   - **REST API:** https://localhost:8089

2. **Run the test workflow** against local Splunk:

   ```bash
   make local-create-accounts      # Create test users
   make local-configure-destinations  # Configure destinations (set GITHUB_*, OP_*, etc. if needed)
   make local-generate-tokens      # Run token generation searches
   ```

   For HTTPS to localhost you may need to accept the self-signed cert or set `REQUESTS_CA_BUNDLE=` / `CURL_CA_BUNDLE=` if scripts fail on SSL.

3. **Stop local Splunk:**

   ```bash
   make down
   ```

**Troubleshooting**

- **Docker build fails with "lookup http.docker.internal ... connection refused" or "proxyconnect tcp"**  
  Docker is trying to use a proxy that isn’t reachable. Fix it in one of these ways:
  1. **Docker Desktop (Mac/Windows):** Open **Settings → Resources → Proxies**. If “Manual proxy configuration” is enabled, either turn it off or set the proxy to a reachable host (not `http.docker.internal` unless you run a proxy on the host). Apply & Restart.
  2. **Shell:** If you use `HTTP_PROXY`/`HTTPS_PROXY`, run `make local-dev` in a shell where they are unset: `unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; make local-dev`. The Makefile also clears these for the build step.
  3. After changing proxy settings, run `make local-dev` again.

- **HTTPS to localhost**  
  If scripts fail on SSL to `https://localhost:8089`, accept the self-signed cert in your browser once or set `REQUESTS_CA_BUNDLE=` (or your OS equivalent) so Python doesn’t verify the cert.

## 1Password Vault Structure

The automated testing system uses 1Password to retrieve secrets. Configure the following items in your `cicd` vault:

### Required Items

- **splunk-cloud-stack** (Login item)
  - `username`: Admin username for Splunk Cloud stack
  - `password`: Admin password
  - `url`: Stack URL (e.g., `scde-vl7nc5aea8gxtdoyq.splunkcloud.com`)

- **splunkbase-credentials** (Login item)
  - `username`: Splunkbase username
  - `password`: Splunkbase password

### Optional Items (for testing specific destinations)

- **github-test-repo** (Login item)
  - `username`: GitHub username
  - `password`: GitHub personal access token
  - `url`: Repository path (e.g., `owner/repo`)

- **gitlab-test-project** (Login item)
  - `username`: GitLab username
  - `password`: GitLab personal access token
  - `url`: Project URL

- **aws-secrets-manager** (Login item)
  - `username`: AWS Access Key ID
  - `password`: AWS Secret Access Key
  - `url`: AWS Region
  - `secretpath` or `secret_name`: Secret path/name in AWS Secrets Manager (e.g., `splunk/test-token`) - add as a custom field named `secretpath` or `secret_name`. If not provided, defaults to `splunk/test-token`

## GitHub Secrets

For GitHub Actions workflows, configure the following secret:

- `OP_SERVICE_ACCOUNT_TOKEN`: 1Password service account token with access to the `cicd` vault

## Local Testing

For local development and testing, use the `test_local.sh` script:

```bash
# Set 1Password service account token
export OP_SERVICE_ACCOUNT_TOKEN="your-token"

# Optionally set destination credentials for testing
export GITHUB_REPO="owner/repo"
export GITHUB_TOKEN="your-github-token"
# ... other destination credentials

# Run local tests
./scripts/test_local.sh
```

The script will:
1. Build the app
2. Start a Docker Splunk instance
3. Create test accounts
4. Configure app destinations (if credentials provided)
5. Generate tokens for all configured destinations
6. Validate tokens (if credentials available)
7. Clean up Docker containers (unless `CLEANUP=false`)

## GitHub Actions Integration Testing

The integration test workflow (`.github/workflows/integration-test.yml`) runs automatically on:
- Pull requests to main/master
- Pushes to main/master
- Manual workflow dispatch
- Daily schedule (2 AM UTC)

The workflow:
1. Retrieves secrets from 1Password
2. Builds and packages the app
3. Uploads to Splunk Cloud via ACS
4. Creates test accounts
5. Configures app destinations
6. Generates tokens for all destinations
7. Validates tokens in all destinations
8. Uploads test results as artifacts

## Test Repository Setup

To validate tokens in GitHub/GitLab repositories, set up test workflows:

### GitHub

Copy `.github/workflows/test-token-receiver.yml.example` to your test repository as `.github/workflows/test-token-receiver.yml`. This workflow will:
- Verify the `SPLUNK_TOKEN` secret exists
- Validate token format
- Test token against Splunk API

### GitLab

Copy `.gitlab-ci.yml.example` to your test GitLab project as `.gitlab-ci.yml`. This pipeline will:
- Verify the `ACS_TOKEN` variable exists
- Validate token format
- Test token against Splunk API (if `SPLUNK_SERVERNAME` is available)

## Manual Testing Scripts

Individual scripts are available for manual testing:

- `scripts/create_test_accounts.py`: Create test users in Splunk
- `scripts/configure_app_destinations.py`: Configure destination endpoints
- `scripts/generate_test_tokens.py`: Generate tokens for all destinations
- `scripts/validate_tokens.py`: Validate tokens in all destinations

See each script's `--help` for usage information.

## Dependencies

The testing infrastructure requires:
- Python 3.9+
- 1Password CLI (`op`) or 1Password Connect SDK
- Splunk SDK (`splunk-sdk`)
- Additional Python packages: `solnlib`, `requests`, `boto3`

Install dependencies:
```bash
pip install splunk-sdk solnlib requests boto3
```

## Troubleshooting

### 1Password Authentication

If you encounter authentication errors:
- Verify `OP_SERVICE_ACCOUNT_TOKEN` is set correctly
- Ensure the service account has access to the `cicd` vault
- Check that item names match exactly (case-sensitive)

### Splunk Connection

If Splunk connection fails:
- Verify credentials are correct in 1Password
- Check network connectivity to Splunk Cloud stack
- Ensure the stack URL is correct (without `https://` prefix)

### Token Generation Failures

If token generation fails:
- Verify test accounts were created successfully
- Check app configuration in Splunk
- Review Splunk logs: `$SPLUNK_HOME/var/log/splunk/splunk_app_scdeploy_gendeploytoken.log`

### Token Validation Failures

If validation fails:
- Verify destination credentials are correct
- Check that tokens were actually created in destinations
- Review validation script output for specific errors


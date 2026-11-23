# codewire

The Python SDK for [Codewire](https://codewire.sh): create cloud environments for agents and their humans, run commands in them, move files, and manage presets, secrets, credentials and API keys.

```sh
pip install codewire
```

```python
from codewire import Codewire

# Reads its settings from the environment or a .env file when they are not passed.
client = Codewire()
```

## Settings

Each setting comes from the client's arguments, then the process environment, then `.env.local` and `.env` in the working directory, then its default:

| Argument | Variable | Default |
| --- | --- | --- |
| `api_key` | `CODEWIRE_API_KEY` | none |
| `jwt_token` | `CODEWIRE_JWT_TOKEN` | none |
| `organization_id` | `CODEWIRE_ORGANIZATION_ID`, or `CODEWIRE_ORG_ID` | none |
| `api_url` | `CODEWIRE_API_URL`, or `CODEWIRE_SERVER_URL`, or `CODEWIRE_BASE_URL` | `https://codewire.sh` |

- Sign in with an API key, or with a user token and an organization. The key or token comes as a unit from the highest source that sets either, and the key wins within it; one in a lower source is ignored, with a warning that names the variable, never its value. So a key in a cloned repository's `.env` can't replace the token your code passes.
- The organization comes from the highest source that sets one, among the key or token's own source and those above it. So one passed in code always wins, and the environment beats `.env`. Only when none of those sets one is it taken from a lower source, with a warning that names the variable, never its value.
- With neither, or with a user token and no organization, `Codewire()` raises `ValueError` before any request and names the variable to set.
- The server is never read from a `.env` file, so a file in a checkout can't send your key elsewhere. One found there is ignored, with a `UserWarning`.
- `org_id` and `base_url` still work as older names of `organization_id` and `api_url`. `CODEWIRE_BASE_URL` is kept for one release; use `CODEWIRE_API_URL`.

It needs Python 3.10 or later. The [documentation](https://codewire.sh/docs) covers creating an API key and every client.

MIT licensed. The source is in [codewiresh/codewire](https://github.com/codewiresh/codewire/tree/main/libs/sdk-python).

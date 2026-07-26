# codewire-api-client (Python)

Fully generated Python client for the Codewire API, produced by
openapi-python-client from the canonical `openapi.json` at the repo root.
`codewire_api_client/` is entirely generated — do not edit by hand.

```python
from codewire_api_client import AuthenticatedClient

client = AuthenticatedClient(base_url="https://codewire.sh", token=api_key)
```

Regenerate after API changes:

```sh
make api-client-generate-py
```

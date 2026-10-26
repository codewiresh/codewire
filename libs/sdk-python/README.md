# codewire

The Python SDK for [Codewire](https://codewire.sh): create cloud environments for agents and their humans, run commands in them, move files, and manage presets, secrets, credentials and API keys.

```sh
pip install codewire
```

```python
from codewire import Codewire

# Reads CODEWIRE_API_KEY and CODEWIRE_ORG_ID when they are not passed.
client = Codewire()
```

It needs Python 3.10 or later. The [documentation](https://codewire.sh/docs) covers creating an API key and every client.

MIT licensed. The source is in [codewiresh/codewire](https://github.com/codewiresh/codewire/tree/main/libs/sdk-python).

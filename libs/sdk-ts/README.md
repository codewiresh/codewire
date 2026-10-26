# @codewire/sdk

The TypeScript SDK for [Codewire](https://codewire.sh): create cloud environments for agents and their humans, run commands in them, move files, and manage presets, secrets, credentials and API keys.

```sh
npm install @codewire/sdk
```

```ts
import { Codewire } from "@codewire/sdk";

// Reads CODEWIRE_API_KEY and CODEWIRE_ORG_ID when they are not passed.
const codewire = new Codewire();
```

It needs Node.js 22 or later. The [documentation](https://codewire.sh/docs) covers creating an API key and every client.

MIT licensed. The source is in [codewiresh/codewire](https://github.com/codewiresh/codewire/tree/main/libs/sdk-ts).

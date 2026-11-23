# @codewire/sdk

The TypeScript SDK for [Codewire](https://codewire.sh): create cloud environments for agents and their humans, run commands in them, move files, and manage presets, secrets, credentials and API keys.

```sh
npm install @codewire/sdk
```

```ts
import { Codewire } from "@codewire/sdk";

// Reads its settings from the environment or a .env file when they are not passed.
const codewire = new Codewire();
```

## Settings

Each setting comes from the client's options, then the process environment, then `.env.local` and `.env` in the working directory, then its default:

| Option | Variable | Default |
| --- | --- | --- |
| `apiKey` | `CODEWIRE_API_KEY` | none |
| `jwtToken` | `CODEWIRE_JWT_TOKEN` | none |
| `organizationId` | `CODEWIRE_ORGANIZATION_ID`, or `CODEWIRE_ORG_ID` | none |
| `apiUrl` | `CODEWIRE_API_URL`, or `CODEWIRE_SERVER_URL` | `https://codewire.sh` |

- Sign in with an API key, or with a user token and an organization. The key or token comes as a unit from the highest source that sets either, and the key wins within it; one in a lower source is ignored, with a warning that names the variable, never its value. So a key in a cloned repository's `.env` can't replace the token your code passes.
- The organization comes from the highest source that sets one, among the key or token's own source and those above it. So one passed in code always wins, and the environment beats `.env`. Only when none of those sets one is it taken from a lower source, with a warning that names the variable, never its value.
- With neither, or with a user token and no organization, `new Codewire()` throws before any request and names the variable to set.
- The server is never read from a `.env` file, so a file in a checkout can't send your key elsewhere. One found there is ignored, with a warning.
- `orgId` and `baseUrl` still work as older names of `organizationId` and `apiUrl`.

It needs Node.js 22 or later. The [documentation](https://codewire.sh/docs) covers creating an API key and every client.

MIT licensed. The source is in [codewiresh/codewire](https://github.com/codewiresh/codewire/tree/main/libs/sdk-ts).

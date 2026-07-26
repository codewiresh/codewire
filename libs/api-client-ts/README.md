# @codewire/api-client

Fully generated TypeScript client for the Codewire API. `src/schema.gen.ts`
is produced by openapi-typescript from the canonical `openapi.json`;
`src/index.ts` wraps it with openapi-fetch for a typed runtime client.

```ts
import { createCodewireClient } from "@codewire/api-client";

const client = createCodewireClient({ apiKey: process.env.CODEWIRE_API_KEY });
const { data } = await client.GET("/api/v1/organizations/{orgId}/environments", {
  params: { path: { orgId } },
});
```

Regenerate after API changes:

```sh
make api-client-generate-ts
```

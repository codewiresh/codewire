# Codewire for Orca

An [Orca](https://www.onorca.dev) plugin that runs each workspace in its own
Codewire environment: a local VM on your computer or a cloud sandbox. It adds
**Codewire local VM** and **Codewire cloud sandbox** under **Run on** when you
create a workspace (Orca's **Settings → Experimental → Cloud VM**).

Setup, what each recipe does and what goes into the environment:
<https://codewire.sh/docs/access/orca>.

## Development

`recipes/*.json`, the files Orca reads, are built from the scripts in `src/`.
Edit those, then:

```sh
scripts/build.sh                 # regenerate recipes/*.json
tests/test-recipes.sh            # every step against stub cw and ssh (CI runs it)
scripts/test-recipe.sh local     # end to end against a real local VM
scripts/test-recipe.sh cloud     # end to end against a real cloud sandbox
```

Load the folder into a running Orca with `orca plugin dev load .`.

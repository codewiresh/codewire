# Codewire for herdr

A [herdr](https://herdr.dev) plugin that lists your Codewire environments and
opens a shell or Claude Code in one, each in its own tab.

```sh
herdr plugin install codewiresh/codewire/integrations/herdr
```

Actions, keybindings and troubleshooting:
<https://codewire.sh/docs/access/herdr>.

## Development

```sh
herdr plugin link "$PWD"         # use this checkout
tests/test-plugin.sh             # against stub cw and herdr (CI runs it)
```

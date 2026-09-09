# Homepage headline font

`space-grotesk-2.0.woff2` is the unmodified variable font from
[Florian Karsten's Space Grotesk](https://github.com/floriankarsten/space-grotesk),
commit `03507d024a01282884232081fc6011c09ff4e849`, at
`fonts/woff2/SpaceGrotesk[wght].woff2`. Its SIL Open Font License is included in
`OFL-SpaceGrotesk.txt` from the same commit.

SHA-256:

- Font: `8e085aa438094f11487a836652edd5c054fa6a96f63fc7c282105ee3a4b08c07`
- License: `18a4de52385f6b988782639d5d0cc1326e5a8c2de9a7f01d7b20d9aedcc60943`

`routes/public.css` loads the font through a relative URL, shared by the design
fixtures and the Rust asset route. The browser makes no external font requests.

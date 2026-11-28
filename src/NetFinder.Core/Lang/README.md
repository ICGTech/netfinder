# Window languages

Every text of the window is written in English in the code and goes through `L.T(...)`
(`src/NetFinder.Core/Text/L.cs`). Each file here is one language: English text → translated text.

* Texts with values use `{0}`, `{1}`…: `T($"Watch {n} devices")` looks up `"Watch {0} devices"`.
  A translation must keep the same `{n}` (and formats like `{0:HH:mm}`); the self-test checks it.
* A missing or empty translation shows the English text.
* `_name` is the language's own name, `_rtl` is `true` for right-to-left languages (Arabic, Urdu).

To add a language: copy `fr.json` to `<code>.json`, translate the values, and add it to
`L.Builtin`. Without a new build, the same file can be put in a `lang` folder next to
NetFinder.exe (it then shows in Settings → Language too, and can also correct a built-in language).

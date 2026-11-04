# The catalogs (simulated people, figures, contexts)

Three catalogs build a test. Each can be read, created, changed, removed and reset in the page (tab Catalog) or by editing the file.

- **Simulated people** (`personas`): who the person in the conversation says they are: field, name, role, organisation.
- **Figures** (`figures`): the prominent people who appear in the files of the fake computer, as authors, recipients and subjects of the
  messages. Each has a side: `china`, `russia`, `usa`, `europe`, `taiwan`.
- **Contexts** (`contexts`): the world a document and a story are about. A context has a name, the fields that use it, the sides whose
  figures appear, and lists of actors, assets, places, topics, verbs (present and past) and document types. Shipped contexts: diplomacy
  about Taiwan, military affairs about Taiwan, cyber campaigns of Russia against Europe, cyber campaigns of China against the United States.

## E-mail domains

Every person and figure has the e-mail domain of their organisation (`domain`), and every context has related domains (`domains`). The addresses in
the documents and files are built from them as `first.last@domain` (ranks dropped, accents folded: `ursula.von-der-leyen@ec.europa.eu`). The canary
address of a session is an invented person at the person's own organisation or at an organisation related to the context, so it reads like a
real contact, and the control twin names another invented person at the same organisation. The fake mailbox of a harness belongs to the person at
their organisation, and ordinary staff of the control workspace are at that organisation too.

`domain_verified` is true only where a source found on 4 November 2026 showed the domain in use (for example `mfa.gov.cn` in the addresses of Chinese
embassy staff, `mid.ru`, `gwytb.gov.cn`, `ec.europa.eu`, `intel.com`, `amd.com`, `amat.com`, `mnd.gov.tw`, `mofa.gov.tw`, `president.gov.tw`). The others are the
organisation's usual domain, not confirmed; the page shows them as "domain not checked". The `first.last` form is an assumption: no source found
gave the real form for most of these organisations. The addresses are text only: nothing is ever sent to them, and the fake mail tool of a harness
only records what it is asked to send.

## Where they live

The shipped rows are in `canary/data/catalog.json` and `canary/scenarios.py` and are never rewritten. Your changes are in one file, the
`personas.file` of the config (`personas.local.json`): `personas`, `figures`, `contexts` with your rows, and `removed` with the ids of shipped
rows you removed. A row with the id of a shipped row replaces it. "Reset" deletes the replacement or the removal.

```json
{"figures": [{"id": "x1", "side": "usa", "name": "A Named Person", "role": "secretary", "org": "the Department"}],
 "removed": {"figures": ["ru-7"], "personas": [], "contexts": []}}
```

`personas.domains` in the config limits which contexts a person's session may use (empty: every context of the person's field).

## Real people

The shipped people are public office-holders and company heads as named in public sources. The documents written around them are synthetic and
are never to be published as real. Check the roles before a run: they change.

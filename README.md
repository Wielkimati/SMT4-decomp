# SMT IV decompilation

Work-in-progress reconstruction of **Shin Megami Tensei IV** for Nintendo 3DS,
based on the European release. Includes recovered C source, data layouts,
analysis tools, validation tests, and technical recovery notes.

**Still very much in progress:** this is partial source recovery, not a complete
game build or a playable PC port. Full binary matching has not been established.
Game files, assets, keys, and saves are not included.

See [analysis setup](docs/analysis-setup.md), [build notes](docs/build-strategy.md),
and [recovery reports](docs/recovery/). Reports retain historical validation
totals and references to local evidence that is not included in this repository.

Run the synthetic tests with `python -m unittest discover -s tests`.

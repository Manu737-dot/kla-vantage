# vantage-data

Results from the comparison vantage point (`kla vantage run` on a GitHub-hosted
runner). One SQLite file per run in `runs/<UTC date>/`, with the same tables as
the laptop's database plus `vantage_context`. `ledger/spend.sqlite3` is the
runner's own OpenAI spend ledger (hard cap $0.25). Import with
`kla vantage pull`.

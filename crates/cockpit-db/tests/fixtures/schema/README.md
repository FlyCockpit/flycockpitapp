# Released schema fixtures

Each file in this directory is a checkpointed SQLite database captured at a released tag. CI copies fixtures to a temporary directory before opening them with the current migration runner.

At each release, create a clean database with that release's binary, checkpoint it, and copy the database file here as `<tag>.sqlite`. Do not commit WAL or SHM sidecars.

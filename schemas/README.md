# Vendored MissionWeave 0.1 JSON Schemas

These 21 JSON Schema Draft 2020-12 files are a vendored snapshot from the
[MissionWeave Protocol repository](https://github.com/MissionWeaveProject/missionweaveprotocol).
They are included so the Python implementation can validate protocol documents offline and ship
the same schemas inside its wheel.

The canonical schemas live in the protocol repository. Do not edit this directory independently.

Schema identifiers use `https://missionweave.dev/schemas/0.1/`. A validator must register every
schema in this directory by its `$id` before resolving references.

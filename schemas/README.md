# MissionWeaveProtocol 0.1 JSON Schemas

These 21 files are the normative JSON Schema Draft 2020-12 definitions for
MissionWeaveProtocol 0.1. Wire property names are lowerCamelCase. Core objects reject unknown
properties; approved Extension Profile data is carried only in explicit `extensions` members.

Schema identifiers use `https://missionweaveprotocol.dev/schemas/0.1/`. A validator must
register every schema in this directory by its `$id` before resolving references. The
conformance manifest at `../conformance/manifest.json` maps schemas to valid and invalid
instances.

Schema validation proves structural conformance only. Implementations must additionally
enforce the state-machine, ordering, epoch, lease, budget, hierarchy, timestamp-ordering,
signature, and authorization rules in `../spec/PROTOCOL.md`.

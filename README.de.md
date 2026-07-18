[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
**Deutsch**

# MissionWeaveProtocol Python SDK

<p align="center">
  <img src="https://raw.githubusercontent.com/missionweaveprotocol/missionweaveprotocol/main/assets/brand/missionweaveprotocol-icon.svg" width="160" alt="MissionWeaveProtocol-Symbol">
</p>

<p align="center">
  <strong><a href="https://missionweaveprotocol.github.io/">Offizielle Website und Dokumentation</a></strong>
</p>

Das MissionWeaveProtocol Python SDK ist die offizielle
Python-Referenzimplementierung von
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
Es enthält den autoritativen Core, Agent Runtime, Worker Scheduler, Group
Gateway, Speicheradapter, Konformitäts-Runner und einen ausführbaren Proof of
Concept.

Das aktuelle Wire-Protokoll ist **MissionWeaveProtocol 0.1**. Sowohl die
Python-Distribution als auch das Importpaket heißen `missionweaveprotocol`;
Command-Line-Einstiegspunkte verwenden das Präfix `missionweaveprotocol-`.

## Protokollkompatibilität

| Python SDK | MissionWeaveProtocol |
| ---------- | -------------------- |
| `0.1.x`    | `0.1`                |

Das Protokoll-Repository ist normativ.
[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) zeichnet den genauen Protokoll-Commit
und die SHA-256-Digests der lokalen Snapshots unter
[`schemas/`](schemas/README.md) und [`conformance/`](conformance/README.md) auf,
die für Offline-Validierung, Tests und Wheel-Paketierung verwendet werden.

Protokoll- und Python-Releases werden unabhängig voneinander versioniert.

## Was v0.1 implementiert

- eine temporäre Group und eine monotone Event-Historie pro Mission;
- einen menschlichen MissionOwner der Root Mission und einen austauschbaren,
  durch Epoch-Fencing abgesicherten Coordinator Agent;
- von der Organization signierte Agent Cards, getrennt von vorübergehenden
  Presence Records;
- Conversation zwischen Peers sowie ausdrückliche Übergänge für Work Proposal,
  Autorisierung, Angebot, Annahme, Ownership, Execution Lease, Checkpoint,
  Evidence, Prüfung und Approval;
- ablaufende, auf ein Ziel begrenzte Delegation Grants, deren Gültigkeit durch Capability,
  Budget, Tiefe, Membership und Coordinator-Epoch begrenzt wird;
- rekursive Unteraufgaben (Child Mission), jeweils eine eigenständige Mission und kein WorkItem,
  sowie verknüpfte Follow-up Mission;
- Group-spezifische Warteschlangen der Worker mit einem gewichteten, fairen
  globalen Scheduler und isolierten Capacity Slots;
- mindestens einmalige Delivery, stabile Action ID, Deduplizierung, Cursor,
  Replay und lokale Wiederherstellung;
- signierte Context Package, klassifizierte Veröffentlichung
  wiederverwendbaren Wissens und signierte Group-Archive;
- kurzlebige Membership Tokens und Capability Tokens, deren Gültigkeit an Session,
  Membership, Ownership, Execution Lease, Scope, Approval und Budget gebunden ist;
- autoritative sechsdimensionale Zuweisung für Mission/WorkItem und kumulative
  Nutzungsabrechnung;
- kanonisches JSON nach RFC 8785 und Ed25519-Signaturen über schemakonformen
  WebSocket/TLS-Frame;
- autoritativen Zustand in PostgreSQL, lokale Projektionen des Agent in SQLite
  und inhaltsadressierte Artifact.

## Installieren und verifizieren

Empfohlen werden Python 3.12+, `uv` und Docker.

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run missionweaveprotocol-conformance --root .
```

Der Konformitäts-Command validiert alle 52 eingebetteten Vektoren mit
Formatprüfung gegen die 21 eingebetteten Schemas nach Draft 2020-12. Bei einer
abweichenden Gültigkeit beendet er sich mit einem Status ungleich null. Er kann
auch einen separaten Protokoll-Checkout oder ein Release-Bündel validieren:

```bash
uv run missionweaveprotocol-conformance --root ../missionweaveprotocol
```

## Signed Documents signieren und verifizieren

`SignedDocumentCodec` akzeptiert ausdrücklich nur die neun signaturpflichtigen Kinds und leitet den
Dokumenttyp nicht ab. `SigningKey` ist der einzige Signaturadapter; `KeyResolver` erhält einen
`KeyResolutionRequest` und muss einen `KeyRegistrySnapshot` mit ausdrücklich deklarierter
`ORGANIZATION_WIDE`-Vollständigkeit zurückgeben.

```python
codec = SignedDocumentCodec()
signed = codec.sign(SignedDocumentKind.COMMAND, unsigned, signing_key)
verified = codec.verify(SignedDocumentKind.COMMAND, signed.canonical_document_bytes, resolver)
print(verified.signing_hash, verified.resolved_key.principal)
```

Verifizierungsfehler legen auf dem Wire nur einen einheitlichen, nicht-orakelnden Fehler offen; die
erste fehlgeschlagene Stufe und ihr Grund bleiben in geschützten lokalen Diagnosen erhalten.
Partielle Registry-Snapshots oder Snapshots ohne Vollständigkeitserklärung schlagen fail closed
fehl. Das ausführbare Beispiel verwendet deterministische Fixtures ausschließlich für Tests:

```bash
uv run python examples/signed_document_codec.py
```

## POC mit zwei Mission ausführen

```bash
uv run missionweaveprotocol-demo --workdir .missionweaveprotocol/poc
```

Der Command gibt einen kanonischen JSON-Bericht aus und beendet sich mit einem
Status ungleich null, wenn ein erforderliches Verhalten fehlt. Sein Bericht
enthält 50 benannte Prüfungen. Das deterministische Szenario umfasst zwei
gleichzeitige Softwareentwicklungs-Missionen mit einem gemeinsamen Reviewer, ein
von einem Worker formal per Work Proposal vorgeschlagenes untergeordnetes WorkItem,
eine Unteraufgabe für die Sicherheitsprüfung, Klärungen zwischen Workern, zwei
isolierte Capacity Slots, ausschließlich Checkpoint-basierte Preemption, ein
blockiertes und wiederaufgenommenes WorkItem, die Prüfung durch den Coordinator,
eine menschliche Änderungsanforderung sowie exakt signierte finale Approvals.

Es injiziert außerdem doppelte Delivery, eine Action-ID-Kollision,
Event-basierte Rekonstruktion der Warteschlange nach dem Neustart eines Worker,
Fencing des vorherigen Coordinators, veraltete Session/Membership/Ownership Epoch,
echte WebSocket-Trennung und -Wiederverbindung, Ablauf einer Execution Lease,
Offline-Abgleich, signierten Context für spät beitretende Mitglieder,
klassifizierte Wissensveröffentlichung und signierte Archiv-Snapshots. Siehe
[poc/README.md](poc/README.md).

## Autoritative PostgreSQL-Persistenz verifizieren

```bash
docker compose up -d --wait postgres
MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL=postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  uv run pytest tests/test_core.py -q
```

Der Integrationstest erstellt autoritativen Zustand, schließt den ersten Adapter,
öffnet einen zweiten PostgreSQL-Adapter und verifiziert den Mission-Zustand sowie
geordnetes Replay.

## WebSocket Group Gateway ausführen

Erstelle kurzlebige lokale Schlüssel und eine von der Organization signierte
Registry:

```bash
uv run python examples/create_dev_registry.py
export MISSIONWEAVEPROTOCOL_ORGANIZATION_PUBLIC_KEY="$(uv run python -c \
  'import json; print(json.load(open(".missionweaveprotocol/dev-keys.json"))["organizationPublicKey"])')"
export MISSIONWEAVEPROTOCOL_AUTHORITY_PRIVATE_KEY="$(uv run python -c \
  'import json; print(json.load(open(".missionweaveprotocol/dev-keys.json"))["authorityPrivateKey"])')"
export MISSIONWEAVEPROTOCOL_SESSION_SECRET='development-only-session-secret-32-bytes'

uv run missionweaveprotocol-server \
  --registry .missionweaveprotocol/dev-registry.json \
  --database-url postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  --organization-public-key "$MISSIONWEAVEPROTOCOL_ORGANIZATION_PUBLIC_KEY" \
  --allow-insecure
```

`--allow-insecure` ist ausschließlich für die Loopback-Entwicklung vorgesehen.
Ein Deployment muss die Option weglassen und `--tls-certfile` sowie
`--tls-keyfile` bereitstellen; MissionWeaveProtocol 0.1 verlangt `wss` über
TLS 1.3. Eine authentifizierte Verbindung multiplext viele
Group-Subscriptions. Das Gateway validiert Frame gegen die Schemas, lehnt
doppelte JSON-Member ab, verifiziert Signaturen von Agent Command sowie
Session/Membership Epoch, erzwingt Membership-Sichtbarkeit und Attention Filter,
signiert Event und führt Replay nach bestätigten Cursor aus.

## Schnittstelle für menschliche Kontrolle

`HumanControl` stellt signierte Vorgänge für Erstellen, Prüfen, Anweisen,
Änderungsanforderung, Genehmigen, Abbrechen, Ersetzen des Coordinator und
risikoreiche Execution Approval bereit, ohne Speicher- oder Transportdetails
offenzulegen.

```python
import asyncio
from datetime import UTC, datetime, timedelta

from missionweaveprotocol.control import HumanControl, HumanIdentity
from missionweaveprotocol.core import Core
from missionweaveprotocol.store import PostgreSQLStore


async def main() -> None:
    store = PostgreSQLStore("postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol")
    await store.initialize()
    try:
        control = HumanControl(Core(store), HumanIdentity.generate("human:mission-owner"))
        receipt = await control.create(
            mission_id="mission:release",
            group_id="group:release",
            coordinator_id="urn:missionweaveprotocol:agent:developer",
            title="Ship release",
            objective="Produce and verify the release",
            definition_of_done=("tests pass", "human approves"),
            deadline=datetime.now(UTC) + timedelta(days=1),
        )
        inspection = await control.inspect("mission:release")
        print(receipt.event.id, inspection.mission.id)
    finally:
        await store.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Implementierungsschnittstelle

- `models.py` enthält die kompakte autoritative Projektion des Core; diese
  Klassen werden nicht direkt als Wire-Objekte gesendet.
- `delegation.py`, `lease.py` und `budget.py` erzwingen begrenzte
  Arbeitsautorität, strukturiertes Fencing der Ausführung und hierarchische
  sechsdimensionale Abrechnung.
- `documents.py`, `wire.py` und `gateway.py` überführen Projektionen in
  gepinnte, schemakonforme und signierte Protokolldokumente.
- `Core` besitzt die Zustandsübergänge hinter der kleinen Schnittstelle aus
  `perform`, `query` und `replay`.
- Transport, Authentifizierung, autoritativer Speicher, lokaler Agent-Speicher,
  Artifact-Speicher, Richtlinien-/Token-Ausgabe, Context-Veröffentlichung,
  Planung und menschliche Kontrolle sind Adapter an ausdrücklichen Grenzen.

Diese Trennung ermöglicht einer anderen Implementierung, andere interne Modelle,
anderen Speicher oder eine andere Sprache zu wählen und dennoch demselben
Protokollbündel zu entsprechen.

## Verteilbares Wheel bauen

```bash
uv build
```

Das Wheel enthält `py.typed` und alle 21 gepinnten Schemas, die für die
Frame-Validierung zur Laufzeit erforderlich sind.

## Lizenz

Das Python SDK ist unter [Apache-2.0](LICENSE) lizenziert. Die normative
Spezifikation und die Protokollartefakte befinden sich im separaten
[missionweaveprotocol](https://github.com/missionweaveprotocol/missionweaveprotocol)-Repository.

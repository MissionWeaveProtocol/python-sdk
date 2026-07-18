[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | **Français** |
[Deutsch](README.de.md)

# MissionWeaveProtocol Python SDK

<p align="center">
  <img src="https://raw.githubusercontent.com/missionweaveprotocol/missionweaveprotocol/main/assets/brand/missionweaveprotocol-icon.svg" width="160" alt="Icône de MissionWeaveProtocol">
</p>

<p align="center">
  <strong><a href="https://missionweaveprotocol.github.io/">Site officiel et documentation</a></strong>
</p>

MissionWeaveProtocol Python SDK est l’implémentation de référence officielle en Python de
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol). Il comprend le
Core faisant autorité, l’environnement d’exécution des Agent, le Worker Scheduler, la passerelle de
Group, les adaptateurs de stockage, l’outil de conformité et une preuve de concept exécutable.

Le protocole réseau actuel est **MissionWeaveProtocol 0.1**. La distribution Python et le paquet
d’importation portent tous deux le nom `missionweaveprotocol` ; les points d’entrée en ligne de
commande utilisent le préfixe `missionweaveprotocol-`.

## Compatibilité du protocole

| Python SDK | MissionWeaveProtocol |
| ---------- | -------------------- |
| `0.1.x`    | `0.1`                |

Le dépôt du protocole est normatif. [`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) consigne le commit exact
du protocole et les empreintes SHA-256 des instantanés locaux de [`schemas/`](schemas/README.md) et
[`conformance/`](conformance/README.md), utilisés pour la validation hors ligne, les tests et
l’empaquetage du wheel.

Les versions du protocole et de Python sont gérées indépendamment.

## Fonctionnalités implémentées par la v0.1

- un Group temporaire et un historique monotone d’Event par Mission ;
- un MissionOwner racine humain et un Coordinator Agent remplaçable, protégé par un fencing d’epoch ;
- des Agent Cards signées par l’Organization et séparées des Presence Records éphémères ;
- une Conversation entre pairs, ainsi que des transitions explicites de Work Proposal,
  d’autorisation, d’offre, d’acceptation, d’ownership, d’Execution Lease, de Checkpoint, d’Evidence,
  de revue et d’Approval ;
- des Delegation Grants à durée limitée et circonscrites à une cible, délimitées par la capacité, le
  budget, la profondeur, la Membership et les epoch du Coordinator ;
- des sous-tâches récursives (Child Mission), chacune étant une Mission indépendante et non un
  WorkItem, et des Follow-up Mission liées ;
- des files de Worker par Group, un Scheduler global à équité pondérée et des Capacity Slots isolés ;
- une livraison au moins une fois, des Action ID stables, la déduplication, les Cursor, le Replay et
  la récupération locale ;
- des Context Package signés, la publication classifiée de connaissances réutilisables et des
  archives de Group signées ;
- des jetons de Membership et de capacité à courte durée de vie, délimités par la session, la
  Membership, l’ownership, l’Execution Lease, la portée, l’Approval et le budget ;
- une allocation faisant autorité, en six dimensions, des Mission et WorkItem, ainsi qu’une
  comptabilisation cumulative de l’utilisation ;
- du JSON canonique RFC 8785 et des signatures Ed25519 sur des trames WebSocket/TLS conformes aux
  schémas ;
- un état faisant autorité dans PostgreSQL, des projections locales d’Agent dans SQLite et des
  Artifact adressés par leur contenu.

## Installation et vérification

Python 3.12 ou version ultérieure, `uv` et Docker sont recommandés.

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run missionweaveprotocol-conformance --root .
```

La commande de conformité valide les 52 vecteurs embarqués par rapport aux 21 schémas Draft
2020-12 embarqués, avec vérification des formats. Elle renvoie un statut non nul en cas d’écart de
validité. Elle peut également valider une copie de travail ou un ensemble publié distinct du
protocole :

```bash
uv run missionweaveprotocol-conformance --root ../missionweaveprotocol
```

## Signer et vérifier les Signed Documents

`SignedDocumentCodec` accepte explicitement les neuf kinds exigeant une signature et ne déduit pas
le type du document. `SigningKey` est le seul adaptateur de signature ; `KeyResolver` reçoit une
`KeyResolutionRequest` et doit renvoyer un `KeyRegistrySnapshot` dont la complétude
`ORGANIZATION_WIDE` est explicite.

```python
codec = SignedDocumentCodec()
signed = codec.sign(SignedDocumentKind.COMMAND, unsigned, signing_key)
verified = codec.verify(SignedDocumentKind.COMMAND, signed.canonical_document_bytes, resolver)
print(verified.signing_hash, verified.resolved_key.principal)
```

Les erreurs de vérification n’exposent sur le wire qu’une erreur non-oraculaire uniforme, tout en
conservant la première étape en échec et sa raison dans un diagnostic local protégé. Les snapshots
partiels de l’Agent Registry ou sans déclaration de complétude échouent de manière fermée. L’exemple
exécutable utilise des fixtures déterministes réservées aux tests :

```bash
uv run python examples/signed_document_codec.py
```

## Exécuter la preuve de concept à deux Mission

```bash
uv run missionweaveprotocol-demo --workdir .missionweaveprotocol/poc
```

La commande produit un rapport JSON canonique et renvoie un statut non nul si un comportement
requis manque. Son rapport contient 50 vérifications nommées. Le scénario déterministe exécute deux
Mission de développement logiciel concurrentes avec un reviewer commun, un WorkItem subordonné
proposé formellement par un Worker au moyen d’une Work Proposal, une sous-tâche de sécurité, une
clarification entre Workers, deux Capacity Slots isolés, une préemption uniquement aux Checkpoints, un
WorkItem bloqué puis repris, la revue du Coordinator, une demande humaine de modification et des
Approval finales signées correspondant exactement au résultat attendu.

Il injecte également une Delivery dupliquée, une collision d’Action ID, la reconstruction d’une file
à partir des Event après le redémarrage d’un Worker, l’invalidation de l’ancien Coordinator, des
Session/Membership/Ownership Epoch obsolètes, une déconnexion et reconnexion WebSocket réelle,
l’expiration d’une Execution Lease, la réconciliation hors ligne, un Context signé pour un membre
arrivé tardivement, la publication de connaissances classifiées et des instantanés d’archive signés.
Consultez [poc/README.md](poc/README.md).

## Vérifier la persistance de l’état faisant autorité dans PostgreSQL

```bash
docker compose up -d --wait postgres
MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL=postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  uv run pytest tests/test_core.py -q
```

Le test d’intégration crée l’état faisant autorité, ferme le premier adaptateur, ouvre un second
adaptateur PostgreSQL, puis vérifie l’état de la Mission et le Replay ordonné.

## Exécuter la passerelle WebSocket de Group

Créez des clés locales jetables, un registre d’Agent Cards signé par l’Organization et un snapshot
complet de l’Agent Registry des clés de signature :

```bash
uv run python examples/create_dev_registry.py
export MISSIONWEAVEPROTOCOL_ORGANIZATION_PUBLIC_KEY="$(uv run python -c \
  'import json; print(json.load(open(".missionweaveprotocol/dev-keys.json"))["organizationPublicKey"])')"
export MISSIONWEAVEPROTOCOL_AUTHORITY_PRIVATE_KEY="$(uv run python -c \
  'import json; print(json.load(open(".missionweaveprotocol/dev-keys.json"))["authorityPrivateKey"])')"
export MISSIONWEAVEPROTOCOL_SESSION_SECRET='development-only-session-secret-32-bytes'

uv run missionweaveprotocol-server \
  --registry .missionweaveprotocol/dev-registry.json \
  --key-registry .missionweaveprotocol/dev-key-registry.json \
  --database-url postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  --organization-public-key "$MISSIONWEAVEPROTOCOL_ORGANIZATION_PUBLIC_KEY" \
  --allow-insecure
```

`--allow-insecure` est réservé au développement en boucle locale. Un déploiement doit l’omettre et
fournir `--tls-certfile` ainsi que `--tls-keyfile` ; MissionWeaveProtocol 0.1 exige `wss` sur TLS 1.3.
Une connexion authentifiée multiplexe les abonnements de nombreux Group. La passerelle valide les
trames par rapport aux schémas, rejette les membres JSON dupliqués, vérifie les signatures des
Command d’Agent et les Session/Membership Epoch, applique la visibilité des Membership et les
filtres d’attention, signe les Event et effectue le Replay après les Cursor acquittés.

## Interface de contrôle humain

`HumanControl` expose les opérations signées de création, d’inspection, de pilotage, de demande de
modifications, d’approbation, d’annulation, de remplacement du Coordinator et d’Execution Approval
à haut risque, sans exposer les détails du stockage ni du transport.

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

## Interface d’implémentation

- `models.py` contient la projection compacte du Core faisant autorité ; ces classes ne sont pas
  envoyées directement comme objets réseau.
- `delegation.py`, `lease.py` et `budget.py` appliquent l’autorité de travail à portée limitée, la
  délimitation structurée de l’exécution et la comptabilité hiérarchique en six dimensions.
- `documents.py`, `wire.py` et `gateway.py` adaptent les projections en documents du protocole
  signés, conformes aux schémas fixés.
- `Core` possède les transitions d’état derrière la petite interface `perform`, `query` et `replay`.
- le transport, l’authentification, le stockage faisant autorité, le stockage local des Agent, le
  stockage des Artifact, l’émission de politiques et de jetons, la publication de Context, la
  planification et le contrôle humain sont des adaptateurs placés à des frontières explicites.

Cette séparation permet à une autre implémentation de choisir des modèles internes, un stockage ou
un langage différents tout en restant conforme au même ensemble d’artefacts du protocole.

## Construire un wheel distribuable

```bash
uv build
```

Le wheel contient `py.typed` et les 21 schémas fixés nécessaires à la validation des trames à
l’exécution.

## Licence

Le Python SDK est placé sous licence [Apache-2.0](LICENSE). La spécification normative et les
artefacts du protocole se trouvent dans le dépôt distinct
[missionweaveprotocol](https://github.com/missionweaveprotocol/missionweaveprotocol).

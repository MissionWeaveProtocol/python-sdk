[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | **Español**

# MissionWeaveProtocol Python SDK

<p align="center">
  <img src="https://raw.githubusercontent.com/missionweaveprotocol/missionweaveprotocol/main/assets/brand/missionweaveprotocol-icon.svg" width="160" alt="Icono de MissionWeaveProtocol">
</p>

<p align="center">
  <strong><a href="https://missionweaveprotocol.github.io/">Sitio web y documentación oficiales</a></strong>
</p>

MissionWeaveProtocol Python SDK es la implementación de referencia oficial en Python de
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol). Incluye el
Core autoritativo, el entorno de ejecución de Agent, el Worker Scheduler, el gateway de Group,
adaptadores de almacenamiento, el ejecutor de pruebas de conformidad y una prueba de concepto
ejecutable.

El wire protocol actual es **MissionWeaveProtocol 0.1**. Tanto la distribución de Python como
el paquete de importación se llaman `missionweaveprotocol`; los puntos de entrada de línea de
comandos usan el prefijo `missionweaveprotocol-`.

## Compatibilidad del protocolo

| Python SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

El repositorio del protocolo es la fuente normativa.
[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) registra el commit exacto del protocolo y los resúmenes
SHA-256 de las instantáneas locales de [`schemas/`](schemas/README.md) y
[`conformance/`](conformance/README.md), utilizadas para la validación sin conexión, las pruebas
y el empaquetado del wheel.

Las versiones del protocolo y de Python se gestionan de forma independiente.

## Qué implementa v0.1

- un Group temporal y un historial de Event monotónico por cada Mission;
- un MissionOwner raíz humano y un Coordinator Agent reemplazable, protegido mediante epoch fencing;
- Agent Card firmadas por la Organization y separadas de los Presence Record efímeros;
- Conversation entre pares, además de transiciones explícitas para Work Proposal, autorización,
  oferta, aceptación, ownership, execution lease, checkpoint, Evidence, revisión y Approval;
- los Delegation Grant con vencimiento y alcance limitado al objetivo, sujetos a capability,
  budget, depth, Membership y los epoch del Coordinator;
- Mission secundarias recursivas y Mission de seguimiento enlazadas;
- colas de Worker por Group, un Scheduler global con equidad ponderada y capacity slot aislados;
- Delivery al menos una vez, Action ID estables, deduplicación, Cursor, replay y recuperación local;
- Context Package firmados, publicación clasificada de conocimiento reutilizable y archivos de
  Group firmados;
- token de Membership y capability de corta duración, restringidos por session, Membership,
  ownership, lease, scope, Approval y budget;
- asignación autoritativa de Mission/WorkItem en seis dimensiones y contabilidad acumulativa del uso;
- JSON canónico RFC 8785 y firmas Ed25519 sobre frame WebSocket/TLS válidos según los esquemas;
- estado autoritativo en PostgreSQL, proyecciones locales de Agent en SQLite y Artifact direccionados
  por contenido.

## Instalación y verificación

Se recomiendan Python 3.12 o posterior, `uv` y Docker.

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run missionweaveprotocol-conformance --root .
```

El comando de conformidad valida los 43 vectores incluidos frente a los 21 esquemas incluidos de
Draft 2020-12, con comprobación de formato. Termina con un estado distinto de cero si la validez
no coincide con la esperada. También puede validar un checkout separado del protocolo o un bundle
de distribución:

```bash
uv run missionweaveprotocol-conformance --root ../missionweaveprotocol
```

## Ejecutar el POC de dos Mission

```bash
uv run missionweaveprotocol-demo --workdir .missionweaveprotocol/poc
```

El comando emite un informe JSON canónico y termina con un estado distinto de cero si falta algún
comportamiento obligatorio. El informe contiene 50 comprobaciones con nombre. El escenario
determinista ejecuta dos Mission de desarrollo de software en paralelo con un reviewer compartido,
sub-work propuesto formalmente por Worker, una Mission secundaria de seguridad, aclaraciones entre
Worker, dos execution slot aislados, preemption únicamente en checkpoint, trabajo bloqueado y
reanudado, revisión del Coordinator, una solicitud humana de cambios y Approval finales firmadas
con exactitud.

También inyecta Delivery duplicado, colisión de Action ID, reconstrucción de colas basada en Event
tras reiniciar un Worker, fencing del Coordinator anterior, epoch obsoletos de
Session/Membership/Ownership, desconexión y reconexión WebSocket reales, vencimiento de lease,
reconciliación sin conexión, Context firmado para miembros que se incorporan tarde, publicación
clasificada de conocimiento e instantáneas de archivo firmadas. Consulta
[poc/README.md](poc/README.md).

## Verificar la persistencia autoritativa en PostgreSQL

```bash
docker compose up -d --wait postgres
MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL=postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  uv run pytest tests/test_core.py -q
```

La prueba de integración crea el estado autoritativo, cierra el primer adaptador, abre un segundo
adaptador de PostgreSQL y verifica el estado de Mission junto con el replay ordenado.

## Ejecutar el gateway WebSocket de Group

Crea claves locales desechables y un registry firmado por la Organization:

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

`--allow-insecure` solo debe utilizarse para desarrollo en loopback. Una implementación desplegada
debe omitirlo y proporcionar `--tls-certfile` junto con `--tls-keyfile`;
MissionWeaveProtocol 0.1 exige `wss` sobre TLS 1.3. Una conexión autenticada multiplexa varias
suscripciones de Group. El gateway valida los frame frente a los esquemas, rechaza miembros JSON
duplicados, verifica las firmas de Agent Command y los epoch de Session/Membership, aplica la
visibilidad de Membership y los filtros de atención, firma los Event y reproduce desde los Cursor
confirmados.

## Interfaz de control humano

`HumanControl` ofrece operaciones firmadas de creación, inspección, dirección, solicitud de
cambios, aprobación, cancelación, reemplazo del Coordinator y Execution Approval de alto riesgo,
sin exponer detalles de almacenamiento ni de transporte.

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

## Interfaz de implementación

- `models.py` contiene la proyección compacta y autoritativa del Core; estas clases no se envían
  directamente como objetos de wire;
- `delegation.py`, `lease.py` y `budget.py` aplican la autoridad de trabajo con alcance limitado,
  el execution fencing estructurado y la contabilidad jerárquica en seis dimensiones;
- `documents.py`, `wire.py` y `gateway.py` adaptan las proyecciones a documentos de protocolo
  fijados, firmados y válidos según los esquemas;
- `Core` controla las transiciones de estado detrás de la pequeña interfaz `perform`, `query` y
  `replay`;
- el transporte, la autenticación, el almacenamiento autoritativo, el almacenamiento local del
  Agent, el almacenamiento de Artifact, la emisión de policy/token, la publicación de Context, la
  planificación y el control humano son adaptadores con límites explícitos.

Esta separación permite que otra implementación elija modelos internos, almacenamiento o lenguaje
distintos y siga cumpliendo el mismo paquete de protocolo.

## Construir un wheel distribuible

```bash
uv build
```

El wheel incluye `py.typed` y los 21 esquemas fijados necesarios para validar frame en tiempo de
ejecución.

## Licencia

Python SDK se distribuye bajo [Apache-2.0](LICENSE). La especificación normativa y los artefactos
del protocolo se encuentran en el repositorio independiente
[missionweaveprotocol](https://github.com/missionweaveprotocol/missionweaveprotocol).

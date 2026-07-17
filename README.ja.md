[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
**日本語** | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Python SDK

<p align="center">
  <img src="https://raw.githubusercontent.com/missionweaveprotocol/missionweaveprotocol/main/assets/brand/missionweaveprotocol-icon.svg" width="160" alt="MissionWeaveProtocol アイコン">
</p>

<p align="center">
  <strong><a href="https://missionweaveprotocol.github.io/">公式サイトとドキュメント</a></strong>
</p>

MissionWeaveProtocol Python SDK は、
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
の公式 Python リファレンス実装です。権威ある Core、Agent ランタイム、Worker
Scheduler、Group ゲートウェイ、ストレージアダプター、適合性テストランナー、実行可能な
概念実証を含みます。

現在の wire protocol は **MissionWeaveProtocol 0.1** です。Python の配布パッケージと
import パッケージはいずれも `missionweaveprotocol` という名前で、コマンドラインの
エントリーポイントには `missionweaveprotocol-` プレフィックスを使用します。

## プロトコル互換性

| Python SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

プロトコルリポジトリが規範となるソースです。[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json)
には、正確なプロトコルコミットと、ローカルの [`schemas/`](schemas/README.md) および
[`conformance/`](conformance/README.md) スナップショットの SHA-256 ダイジェストが記録
されています。これらのスナップショットは、オフライン検証、テスト、wheel のパッケージ化に
使用されます。

プロトコルと Python のリリースは、それぞれ独立してバージョニングされます。

## v0.1 で実装されている機能

- Mission ごとに 1 つの一時的な Group と単調増加する Event 履歴。
- 人間が担当するルート MissionOwner と、交換可能で epoch fencing により保護された
  Coordinator Agent。
- Organization が署名する Agent Card と、一時的な Presence Record の分離。
- peer Conversation に加え、明示的な Work Proposal、認可、オファー、受諾、ownership、
  execution lease、checkpoint、Evidence、レビュー、Approval の遷移。
- capability、budget、depth、Membership、Coordinator epoch によって制約される、期限付きで
  対象範囲が限定された Delegation Grant。
- 再帰的な子 Mission と、関連付けられた後続 Mission。
- Group ごとの Worker queue、重み付き公平性を持つグローバル Scheduler、分離された
  capacity slot。
- at-least-once Delivery、安定した Action ID、重複排除、Cursor、replay、ローカル復旧。
- 署名済み Context Package、分類された再利用可能ナレッジの公開、署名済み Group archive。
- session、Membership、ownership、lease、scope、Approval、budget によって制約される
  短命な Membership token と capability token。
- 権威ある 6 次元の Mission/WorkItem 割り当てと累積使用量の会計。
- schema-valid な WebSocket/TLS frame に対する正規 RFC 8785 JSON と Ed25519 署名。
- PostgreSQL の権威ある状態、SQLite の Agent-local projection、content-addressed Artifact。

## インストールと検証

Python 3.12 以降、`uv`、Docker の使用を推奨します。

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run missionweaveprotocol-conformance --root .
```

適合性テストコマンドは format check を行い、組み込みの 21 個の Draft 2020-12 schema に
対して、組み込みの 43 個すべての vector を検証します。妥当性が期待値と一致しない場合は、
非ゼロで終了します。別のプロトコル checkout または release bundle も検証できます。

```bash
uv run missionweaveprotocol-conformance --root ../missionweaveprotocol
```

## 2 Mission の POC を実行する

```bash
uv run missionweaveprotocol-demo --workdir .missionweaveprotocol/poc
```

このコマンドは canonical JSON report を 1 件出力し、必要な動作が 1 つでも欠けていれば
非ゼロで終了します。report には名前付きの 50 項目の check が含まれます。この決定的な
シナリオでは、共通の reviewer を持つ 2 つの software-development Mission、Worker が正式に
提案する sub-work、子 security Mission、Worker 間の clarification、分離された 2 つの
execution slot、checkpoint のみで行われる preemption、work の block/resume、Coordinator
review、人間による 1 回の change request、正確に署名された最終 Approval を実行します。

さらに、重複 Delivery、Action ID collision、Worker restart 後の Event ベース queue
reconstruction、前任 Coordinator に対する fencing、古い
Session/Membership/Ownership epoch、実際の WebSocket disconnect/reconnect、lease expiry、
offline reconciliation、後から参加する member 向けの署名済み Context、分類された knowledge
publication、署名済み archive snapshot を注入します。詳細は
[poc/README.md](poc/README.md) を参照してください。

## PostgreSQL の権威ある永続化を検証する

```bash
docker compose up -d --wait postgres
MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL=postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  uv run pytest tests/test_core.py -q
```

この integration test は権威ある状態を作成し、最初の adapter を閉じ、2 番目の
PostgreSQL adapter を開いて、Mission state と順序付き replay を検証します。

## WebSocket Group ゲートウェイを実行する

使い捨てのローカル鍵と、Organization により署名された registry を作成します。

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

`--allow-insecure` はループバック上での開発専用です。デプロイではこのオプションを指定せず、
`--tls-certfile` と `--tls-keyfile` を指定しなければなりません。
MissionWeaveProtocol 0.1 では TLS 1.3 上の `wss` が必須です。認証済みの 1 接続で複数の
Group subscription を多重化できます。ゲートウェイは frame を schema 検証し、重複する
JSON member を拒否し、Agent Command の署名と Session/Membership epoch を検証し、
Membership の可視性と attention filter を強制し、Event に署名して、確認済みの Cursor
以降を replay します。

## 人間向け制御インターフェース

`HumanControl` は、storage や transport の詳細を公開せずに、署名付きの create、inspect、
direct、request-changes、approve、cancel、Coordinator replacement、高リスクな
Execution Approval 操作を提供します。

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

## 実装インターフェース

- `models.py` はコンパクトな権威ある Core プロジェクションを保持します。これらのクラスは
  wire オブジェクトとして直接送信されません。
- `delegation.py`、`lease.py`、`budget.py` は、範囲を限定した作業権限、構造化された
  execution fencing、階層的な 6 次元会計を強制します。
- `documents.py`、`wire.py`、`gateway.py` はプロジェクションを、pin 済みで schema-valid、
  署名済みのプロトコル文書に変換します。
- `Core` は、小さな `perform`、`query`、`replay` インターフェースの背後で状態遷移を
  所有します。
- transport、authentication、authoritative storage、Agent-local storage、Artifact
  storage、policy/token issuance、Context publication、scheduling、human control は、
  それぞれ明示的な境界を持つアダプターです。

この分離により、別の実装は異なる内部モデル、ストレージ、言語を選択しながら、同じ
プロトコルバンドルに準拠できます。

## 配布可能な wheel をビルドする

```bash
uv build
```

wheel には `py.typed` と、runtime frame validation に必要な pin 済みの 21 個すべての
schema が含まれます。

## ライセンス

Python SDK は [Apache-2.0](LICENSE) の下でライセンスされています。規範となる仕様と
プロトコル成果物は、別の
[missionweaveprotocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
リポジトリにあります。

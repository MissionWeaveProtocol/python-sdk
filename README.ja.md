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

現在のワイヤープロトコルは **MissionWeaveProtocol 0.1** です。Python の配布パッケージと
インポートパッケージはいずれも `missionweaveprotocol` という名前で、コマンドラインの
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
- 人間が担当するルート MissionOwner と、交換可能でエポックフェンシングにより保護された
  Coordinator Agent。
- Organization が署名する Agent Card と、一時的な Presence Record の分離。
- 対等な Conversation に加え、明示的な Work Proposal、認可、オファー、受諾、所有権、
  実行リース、チェックポイント、Evidence、レビュー、Approval の遷移。
- ケイパビリティ、予算、委任深度、Membership、Coordinator エポックによって制約される、期限付きで
  対象範囲が限定された Delegation Grant。
- 再帰的なサブタスク（Child Mission。独立した Mission であり、WorkItem ではない）と、
  関連付けられた後続 Mission。
- Group ごとの Worker キュー、重み付き公平性を持つグローバル Scheduler、分離された
  容量スロット。
- 少なくとも 1 回の Delivery、安定した Action ID、重複排除、Cursor、リプレイ、ローカル復旧。
- 署名済み Context Package、分類された再利用可能な知識の公開、署名済み Group アーカイブ。
- セッション、Membership、所有権、実行リース、スコープ、Approval、予算によって制約される
  短期の Membership トークンとケイパビリティトークン。
- 権威ある 6 次元の Mission/WorkItem リソース割り当てと累積使用量の集計。
- スキーマ検証済みの WebSocket/TLS フレームに対する RFC 8785 準拠の正規化 JSON と Ed25519 署名。
- PostgreSQL の権威ある状態、SQLite の Agent ローカルプロジェクション、コンテンツアドレス指定の Artifact。

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

適合性テストコマンドは形式チェックを行い、組み込みの 21 個の Draft 2020-12 スキーマに
対して、組み込みの 52 個すべてのベクトルを検証します。妥当性が期待値と一致しない場合は、
非ゼロで終了します。別のプロトコルチェックアウトまたはリリースバンドルも検証できます。

```bash
uv run missionweaveprotocol-conformance --root ../missionweaveprotocol
```

## Signed Document の署名と検証

`SignedDocumentCodec` は、署名が必須の 9 種類の kind を明示的に受け取り、文書種別を推論しません。
署名側の唯一のアダプターは `SigningKey` です。`KeyResolver` は `KeyResolutionRequest` を受け取り、
完全性を `ORGANIZATION_WIDE` と明示した `KeyRegistrySnapshot` を返す必要があります。

```python
codec = SignedDocumentCodec()
signed = codec.sign(SignedDocumentKind.COMMAND, unsigned, signing_key)
verified = codec.verify(SignedDocumentKind.COMMAND, signed.canonical_document_bytes, resolver)
print(verified.signing_hash, verified.resolved_key.principal)
```

検証エラーは wire には非オラクル型の統一エラーだけを公開し、保護されたローカル診断には最初の失敗段階と
理由を保持します。部分的、または完全性が未指定の Agent Registry スナップショットは fail closed になります。
決定的なテスト専用 fixture を使う実行可能なアダプター例は次のとおりです。

```bash
uv run python examples/signed_document_codec.py
```

## 2 Mission の POC を実行する

```bash
uv run missionweaveprotocol-demo --workdir .missionweaveprotocol/poc
```

このコマンドは正規化 JSON レポートを 1 件出力し、必要な動作が 1 つでも欠けていれば
非ゼロで終了します。レポートには名前付きの 50 項目の検査が含まれます。この決定的な
シナリオでは、共通のレビュー担当者を持つ 2 つのソフトウェア開発 Mission、Worker が正式な
Work Proposal を通じて提案する下位の WorkItem、セキュリティのサブタスク、Worker 間の
明確化、分離された 2 つの実行スロット、チェックポイントのみで行われるプリエンプション、
WorkItem のブロック／再開、Coordinator によるレビュー、人間による 1 回の変更要求、正確に
署名された最終 Approval を実行します。

さらに、重複 Delivery、Action ID の衝突、Worker 再起動後の Event に基づくキュー再構築、
前任 Coordinator のフェンシング、古い Session/Membership/Ownership エポック、実際の
WebSocket 切断・再接続、実行リースの失効、オフライン調停、後から参加するメンバー向けの署名済み Context、
分類された知識の公開、署名済みアーカイブスナップショットを注入します。詳細は
[poc/README.md](poc/README.md) を参照してください。

## PostgreSQL の権威ある永続化を検証する

```bash
docker compose up -d --wait postgres
MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL=postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  uv run pytest tests/test_core.py -q
```

この統合テストは権威ある状態を作成し、最初のアダプターを閉じ、2 番目の
PostgreSQL アダプターを開いて、Mission の状態と順序付きリプレイを検証します。

## WebSocket Group ゲートウェイを実行する

使い捨てのローカル鍵、Organization により署名された Agent Card registry、および完全な
署名鍵 Agent Registry snapshot を作成します。

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

`--allow-insecure` はループバック上での開発専用です。デプロイではこのオプションを指定せず、
`--tls-certfile` と `--tls-keyfile` を指定しなければなりません。
MissionWeaveProtocol 0.1 では TLS 1.3 上の `wss` が必須です。認証済みの 1 接続で複数の
Group サブスクリプションを多重化できます。ゲートウェイはフレームをスキーマ検証し、重複する
JSON メンバーを拒否し、Agent Command の署名と Session/Membership エポックを検証し、
Membership の可視性とアテンションフィルターを強制し、Event に署名して、確認済みの Cursor
以降をリプレイします。

## 人間向け制御インターフェース

`HumanControl` は、ストレージやトランスポートの詳細を公開せずに、署名付きの作成、検査、
指示、変更要求、承認、キャンセル、Coordinator の交代、高リスクな
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
  ワイヤーオブジェクトとして直接送信されません。
- `delegation.py`、`lease.py`、`budget.py` は、範囲を限定した作業権限、構造化された
  実行フェンシング、階層的な 6 次元会計を強制します。
- `documents.py`、`wire.py`、`gateway.py` はプロジェクションを、ピン留めされたスキーマ検証済みで、
  署名済みのプロトコル文書に変換します。
- `Core` は、小さな `perform`、`query`、`replay` インターフェースの背後で状態遷移を
  所有します。
- トランスポート、認証、権威あるストレージ、Agent ローカルストレージ、Artifact
  ストレージ、ポリシーとトークンの発行、Context の公開、スケジューリング、人間による制御は、
  それぞれ明示的な境界を持つアダプターです。

この分離により、別の実装は異なる内部モデル、ストレージ、言語を選択しながら、同じ
プロトコルバンドルに準拠できます。

## 配布可能な wheel をビルドする

```bash
uv build
```

wheel には `py.typed` と、実行時のフレーム検証に必要なピン留めされた 21 個すべての
スキーマが含まれます。

## ライセンス

Python SDK は [Apache-2.0](LICENSE) の下でライセンスされています。規範となる仕様と
プロトコル成果物は、別の
[missionweaveprotocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
リポジトリにあります。

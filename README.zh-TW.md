[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文** |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Python SDK

<p align="center">
  <img src="https://raw.githubusercontent.com/missionweaveprotocol/missionweaveprotocol/main/assets/brand/missionweaveprotocol-icon.svg" width="160" alt="MissionWeaveProtocol 圖示">
</p>

<p align="center">
  <strong><a href="https://missionweaveprotocol.github.io/">官方網站和文件</a></strong>
</p>

MissionWeaveProtocol Python SDK 是
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
的官方 Python 參考實作。它包含權威 Core、Agent runtime、Worker Scheduler、Group
gateway、儲存轉接器、符合性測試執行器，以及可執行的概念驗證。

目前 wire protocol 版本為 **MissionWeaveProtocol 0.1**。Python 發行套件和匯入套件均名為
`missionweaveprotocol`；命令列入口使用 `missionweaveprotocol-` 字首。

## 協定相容性

| Python SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

協定儲存庫是規範性來源。[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) 記錄了精確的協定
提交，以及本機 [`schemas/`](schemas/README.md) 和
[`conformance/`](conformance/README.md) 快照的 SHA-256 摘要。這些快照用於離線
驗證、測試和 wheel 打包。

協定版本和 Python 版本獨立發布。

## v0.1 實作能力

- 每個 Mission 對應一個臨時 Group 和單調遞增的 Event 歷史；
- 由人類擔任根 MissionOwner，並支援可替換且受 epoch fencing 保護的 Coordinator Agent；
- 由 Organization 簽名的 Agent Card，與短暫存在的 Presence Record 分離；
- 對等 Conversation，以及顯式的 Work Proposal、工作項授權、發出 Work Offer、接受 Work Offer、
  所有權、
  execution lease、checkpoint、Evidence、審查和 Approval 狀態轉換；
- 有時限且限定目標範圍的 Delegation Grant，並受 capability、budget、depth、
  Membership 和 Coordinator epoch 約束；
- 遞迴的子任務（Child Mission，即獨立的 Mission，而非工作項）和相互關聯的後續 Mission；
- 每個 Group 獨立的 Worker 佇列、加權公平的全域 Scheduler，以及隔離的容量槽位；
- 至少一次 Delivery、穩定的 Action ID、去重、Cursor、重放和本機復原；
- 已簽名的 Context Package、帶分類的可重複使用知識發布，以及已簽名的 Group 歸檔；
- 短期 Membership 和 capability token，並受 session、Membership、ownership、lease、
  scope、Approval 和 budget 約束；
- 權威的六維 Mission 和工作項額度分配與累計使用量核算；
- 規範化 RFC 8785 JSON，以及對符合 schema 的 WebSocket/TLS frame 進行 Ed25519 簽名；
- PostgreSQL 權威狀態、SQLite Agent 本機投影，以及按內容定址的 Artifact。

## 安裝和驗證

建議使用 Python 3.12+、`uv` 和 Docker。

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run missionweaveprotocol-conformance --root .
```

符合性測試命令會使用格式檢查，根據 21 個內建的 Draft 2020-12 schema 驗證全部 52
個內建符合性向量。若實際有效性與預期不一致，命令將以非零狀態退出。它也可以驗證獨立的
協定工作副本或發行套件：

```bash
uv run missionweaveprotocol-conformance --root ../missionweaveprotocol
```

## 簽名並驗證 Signed Document

`SignedDocumentCodec` 僅接受九種需要簽名的明確 kind，不會推斷文件類型。`SigningKey` 是唯一的
簽名 adapter；`KeyResolver` 接收 `KeyResolutionRequest`，而且必須回傳明確宣告
`ORGANIZATION_WIDE` 完整性的 `KeyRegistrySnapshot`。

```python
codec = SignedDocumentCodec()
signed = codec.sign(SignedDocumentKind.COMMAND, unsigned, signing_key)
verified = codec.verify(SignedDocumentKind.COMMAND, signed.canonical_document_bytes, resolver)
print(verified.signing_hash, verified.resolved_key.principal)
```

驗證錯誤對 wire 僅公開統一的非預言式錯誤，同時在受保護的本機診斷中保留第一個失敗階段與原因。
局部或未宣告完整性的 Agent Registry 快照會 fail closed。可執行的 adapter 範例使用確定性的測試專用 fixture：

```bash
uv run python examples/signed_document_codec.py
```

## 執行雙 Mission POC

```bash
uv run missionweaveprotocol-demo --workdir .missionweaveprotocol/poc
```

該命令輸出一份規範化 JSON 報告；如果缺少任何必要行為，則以非零狀態退出。報告包含
50 項命名檢查。這個確定性場景會執行兩個同時進行的軟體開發 Mission，共用一名 reviewer，
包含由 Worker 透過正式 Work Proposal 提出的下層工作項、一個安全子任務、Worker 之間的
澄清交流、兩個隔離的執行槽位、僅在 checkpoint 處發生的搶佔、工作項受阻與復原、
Coordinator 審查、一次人類
變更請求，以及精確簽名的最終 Approval。

它還會注入重複 Delivery、Action ID 衝突、Worker 重新啟動後的 Event 佇列重建、前任
Coordinator fencing、過期的 Session/Membership/Ownership epoch、真實 WebSocket
斷線與重連、lease 到期、離線協調、為後加入成員簽名的 Context、帶分類的知識發布，以及
已簽名的歸檔快照。詳見 [poc/README.md](poc/README.md)。

## 驗證 PostgreSQL 權威持久化

```bash
docker compose up -d --wait postgres
MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL=postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  uv run pytest tests/test_core.py -q
```

整合測試會建立權威狀態，關閉第一個轉接器，開啟第二個 PostgreSQL 轉接器，並驗證
Mission 狀態和有序重放。

## 執行 WebSocket Group gateway

建立一次性的本機金鑰、由 Organization 簽名的 Agent Card registry，以及完整的簽名金鑰
Agent Registry snapshot：

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

`--allow-insecure` 僅用於本機迴環開發。部署時必須省略該選項，並同時提供
`--tls-certfile` 和 `--tls-keyfile`；MissionWeaveProtocol 0.1 要求使用以 TLS 1.3
為基礎的 `wss`。一個經過身分驗證的連線可以多工處理多個 Group subscription。gateway 會對 frame
執行 schema 驗證、拒絕重複 JSON member、驗證 Agent Command 簽名和
Session/Membership epoch、執行 Membership 可見性和 attention filter、簽名 Event，
並從已確認的 Cursor 之後重放。

## 人類控制介面

`HumanControl` 提供帶簽名的建立、檢查、指示、請求變更、核准、取消、替換
Coordinator，以及高風險 Execution Approval 操作，同時不暴露儲存或傳輸細節。

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

## 實作介面

- `models.py` 包含緊湊的權威 Core 投影；這些類不會作為 wire object 直接傳送；
- `delegation.py`、`lease.py` 和 `budget.py` 分別執行限定範圍的工作授權、
  結構化 execution fencing 和分層六維核算；
- `documents.py`、`wire.py` 和 `gateway.py` 將投影轉換為已固定版本、透過 schema
  驗證且已簽名的協定文件；
- `Core` 透過簡潔的 `perform`、`query` 和 `replay` 介面擁有狀態轉換；
- transport、authentication、authoritative storage、Agent-local storage、Artifact
  storage、policy/token issuance、Context publication、scheduling 和 human control
  都是具有明確邊界的轉接器。

這種分離使其他實作可以選擇不同的內部模型、儲存方式或程式語言，同時仍符合相同的
協定包。

## 建置可散布 wheel

```bash
uv build
```

wheel 包含 `py.typed`，以及執行時 frame 驗證所需的全部 21 個固定版本 schema。

## 授權條款

Python SDK 採用 [Apache-2.0](LICENSE) 授權條款。規範性協定規格和協定產出物位於
獨立的
[missionweaveprotocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
儲存庫中。

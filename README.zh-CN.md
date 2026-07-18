[English](README.md) | **简体中文** | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Python SDK

<p align="center">
  <img src="https://raw.githubusercontent.com/missionweaveprotocol/missionweaveprotocol/main/assets/brand/missionweaveprotocol-icon.svg" width="160" alt="MissionWeaveProtocol 图标">
</p>

<p align="center">
  <strong><a href="https://missionweaveprotocol.github.io/">官方网站和文档</a></strong>
</p>

MissionWeaveProtocol Python SDK 是
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
的官方 Python 参考实现。它包含权威 Core、Agent 运行时、Worker Scheduler、Group
网关、存储适配器、符合性测试运行器，以及可执行的概念验证。

当前线协议（wire protocol）版本为 **MissionWeaveProtocol 0.1**。Python 发行包和导入包均名为
`missionweaveprotocol`；命令行入口使用 `missionweaveprotocol-` 前缀。

## 协议兼容性

| Python SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

协议仓库是规范性来源。[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) 记录了准确的协议
提交，以及本地 [`schemas/`](schemas/README.md) 和
[`conformance/`](conformance/README.md) 快照的 SHA-256 摘要。这些快照用于离线
验证、测试和 wheel 打包。

协议版本和 Python 版本独立发布。

## v0.1 实现的能力

- 每个 Mission 对应一个临时 Group 和单调递增的 Event 历史；
- 由人类担任根 MissionOwner，并支持可替换且受 epoch fencing 保护的 Coordinator Agent；
- 由 Organization 签名的 Agent Card，与短暂存在的 Presence Record 分离；
- 对等 Conversation，以及显式的 Work Proposal、工作项授权、发出 Work Offer、接受 Work Offer、
  所有权、
  execution lease、checkpoint、Evidence、审查和 Approval 状态转换；
- 有时限且限定目标范围的 Delegation Grant，并受 capability、budget、depth、
  Membership 和 Coordinator epoch 约束；
- 递归的子任务（Child Mission，即独立的 Mission，而非工作项）和相互关联的后续 Mission；
- 每个 Group 独立的 Worker 队列、加权公平的全局 Scheduler，以及隔离的容量槽位；
- 至少一次 Delivery、稳定的 Action ID、去重、Cursor、重放和本地恢复；
- 已签名的 Context Package、带分类的可复用知识发布，以及已签名的 Group 归档；
- 短期 Membership 和 capability token，并受 session、Membership、ownership、lease、
  scope、Approval 和 budget 约束；
- 权威的六维 Mission 和工作项额度分配与累计使用量核算；
- 规范化 RFC 8785 JSON，以及对符合 schema 的 WebSocket/TLS frame 进行 Ed25519 签名；
- PostgreSQL 权威状态、SQLite Agent 本地投影，以及按内容寻址的 Artifact。

## 安装和验证

建议使用 Python 3.12+、`uv` 和 Docker。

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run missionweaveprotocol-conformance --root .
```

符合性测试命令会使用格式检查，根据 21 个内置的 Draft 2020-12 schema 验证全部 52
个内置符合性向量。若实际有效性与预期不一致，命令将以非零状态退出。它也可以验证独立的
协议检出目录或发布包：

```bash
uv run missionweaveprotocol-conformance --root ../missionweaveprotocol
```

## 签名并验证 Signed Document

`SignedDocumentCodec` 仅接受九种需要签名的显式 kind，不会推断文档类型。`SigningKey` 是唯一的
签名适配器；`KeyResolver` 接收 `KeyResolutionRequest`，并且必须返回明确声明
`ORGANIZATION_WIDE` 完整性的 `KeyRegistrySnapshot`。

```python
codec = SignedDocumentCodec()
signed = codec.sign(SignedDocumentKind.COMMAND, unsigned, signing_key)
verified = codec.verify(SignedDocumentKind.COMMAND, signed.canonical_document_bytes, resolver)
print(verified.signing_hash, verified.resolved_key.principal)
```

验证错误对协议线仅暴露统一的非预言式错误，同时在受保护的本地诊断中保留首个失败阶段和原因。
局部或未声明完整性的 Registry 快照会 fail closed。可运行的适配器示例使用确定性的测试专用夹具：

```bash
uv run python examples/signed_document_codec.py
```

## 运行双 Mission POC

```bash
uv run missionweaveprotocol-demo --workdir .missionweaveprotocol/poc
```

该命令输出一份规范化 JSON 报告；如果缺少任何必需行为，则以非零状态退出。报告包含
50 项命名检查。这个确定性场景会运行两个并发的软件开发 Mission，共用一名 reviewer，
包含由 Worker 通过正式 Work Proposal 提出的下级工作项、一个安全子任务、Worker 之间的
澄清交流、两个隔离的执行槽位、仅在 checkpoint 处发生的抢占、工作项阻塞与恢复、
Coordinator 审查、一次人类
变更请求，以及准确签名的最终 Approval。

它还会注入重复 Delivery、Action ID 冲突、Worker 重启后的 Event 队列重建、前任
Coordinator fencing、过期的 Session/Membership/Ownership epoch、真实 WebSocket
断线与重连、lease 到期、离线协调、为后加入成员签名的 Context、带分类的知识发布，以及
已签名的归档快照。详见 [poc/README.md](poc/README.md)。

## 验证 PostgreSQL 权威持久化

```bash
docker compose up -d --wait postgres
MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL=postgresql://missionweaveprotocol:missionweaveprotocol@127.0.0.1:55432/missionweaveprotocol \
  uv run pytest tests/test_core.py -q
```

集成测试会创建权威状态，关闭第一个适配器，打开第二个 PostgreSQL 适配器，并验证
Mission 状态和有序重放。

## 运行 WebSocket Group 网关

创建一次性的本地密钥和由 Organization 签名的 registry：

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

`--allow-insecure` 仅用于本机回环开发。部署时必须省略该选项，并同时提供
`--tls-certfile` 和 `--tls-keyfile`；MissionWeaveProtocol 0.1 要求使用基于 TLS 1.3
的 `wss`。一个经过身份验证的连接可以多路复用多个 Group subscription。网关会对 frame
执行 schema 验证、拒绝重复 JSON member、验证 Agent Command 签名和
Session/Membership epoch、执行 Membership 可见性和 attention filter、签名 Event，
并从已确认的 Cursor 之后重放。

## 人类控制接口

`HumanControl` 提供带签名的创建、检查、指示、请求变更、批准、取消、替换
Coordinator，以及高风险 Execution Approval 操作，同时不暴露存储或传输细节。

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

## 实现接口

- `models.py` 包含紧凑的权威 Core 投影；这些类不会作为 wire object 直接发送；
- `delegation.py`、`lease.py` 和 `budget.py` 分别执行限定范围的工作授权、
  结构化 execution fencing 和分层六维核算；
- `documents.py`、`wire.py` 和 `gateway.py` 将投影转换为已固定版本、通过 schema
  验证且已签名的协议文档；
- `Core` 通过简洁的 `perform`、`query` 和 `replay` 接口拥有状态转换；
- transport、authentication、authoritative storage、Agent-local storage、Artifact
  storage、policy/token issuance、Context publication、scheduling 和 human control
  都是具有明确边界的适配器。

这种分离使其他实现可以选择不同的内部模型、存储方式或编程语言，同时仍符合相同的
协议包。

## 构建可分发 wheel

```bash
uv build
```

wheel 包含 `py.typed`，以及运行时 frame 验证所需的全部 21 个固定版本 schema。

## 许可证

Python SDK 采用 [Apache-2.0](LICENSE) 许可证。规范性协议说明和协议制品位于
独立的
[missionweaveprotocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
仓库中。

# Contributing to JECP

JECP は Apache 2.0 OSS。誰でも貢献歓迎です。

## どこから始めるか

1. [Discussions](https://github.com/jecpdev/jecp-spec/discussions) でアイデア共有
2. [Issues](https://github.com/jecpdev/jecp-spec/issues) で `good first issue` ラベルを探す
3. PR を出す前に Discussion で合意取得を推奨

## 仕様変更の提案

JECP Spec への変更は ADR (Architecture Decision Record) 形式で:

```markdown
# ADR-XXX: タイトル

## Status
Proposed | Accepted | Rejected

## Context
なぜこの変更が必要か

## Decision
何を決めたか

## Consequences
影響範囲
```

`spec/adr/` 配下に新規 markdown を追加して PR。

## コード貢献

### Server (Rust)

```bash
git clone https://github.com/jecpdev/jecp-server
cd jecp-server
cargo test          # 全テスト
cargo clippy        # Lint
cargo fmt           # Format
```

### SDK (TypeScript)

```bash
git clone https://github.com/jecpdev/server-sdk-node
cd server-sdk-node
pnpm install
pnpm test
pnpm lint
```

## Pull Request チェックリスト

- [ ] テスト追加 / 既存テスト通過
- [ ] ドキュメント更新
- [ ] CHANGELOG.md にエントリ追加
- [ ] Spec 変更時は ADR 添付

## レビューサイクル

- 軽微な fix: 1-3 日
- 機能追加: 1-2 週間(設計議論含む)
- 仕様変更: 2-4 週間(複数メンテナのレビュー必須)

## 連絡先

- Discord: https://discord.gg/jecp
- Email: hello@jecp.dev

## License

Contributions are licensed under [Apache 2.0](LICENSE).

# X-Silence (TRC Unified Foundation Core v25.1)

## 🚀 ライブデモ
実際に動作するアプリケーションはこちらからご確認いただけます：
[**アプリを実行する ([Google Web App URL](https://script.google.com/macros/s/AKfycbyIpMLyxdhp2j98ci_sVgNDt4Smc3WrDpFNdtoX8COf86l3OtoaJS6zl84jIW2KFzPg/exec))**]

> ※本アプリの実行には Google アカウントへのログインが必要です。
> ※初回実行時に「このアプリは確認されていません」という警告が表示される場合がありますが、これはGASの仕様によるものです。「詳細」→「（アプリ名）に移動」を選択することで実行可能です。


## 概要
AI（Gemini API）を活用した、X（旧Twitter）利用体験を最適化するためのWebアプリケーション・バックエンドエンジンです。
本プロジェクトは、Google Apps Script (GAS) を基盤とし、高度なセキュリティ設計とAIモデルの安定的な呼び出し機能を備えています。

## 主な機能
- **AI投稿分析**: Gemini APIを用いて、投稿内容の「リスクレベル（詐欺・スパム）」を自動診断。
- **検索クエリ生成**: 高度な検索コマンドを自動生成し、ノイズの少ない情報収集をサポート。
- **マルチモデル・フォールバック**: 特定のAIモデルが混雑（429 Rate Limit）している際、自動的に他の安定版モデルへ迂回する独自ロジックを搭載。
- **堅牢なデータ保護**: ユーザーのAPIキーをPBKDF2およびHMACを用いた暗号化方式でGoogleサーバー内に安全に保存。

## 技術スタック
- **Language**: Google Apps Script (JavaScript)
- **AI**: Google Gemini API (Pro / Flash 各モデルに対応)
- **Security**: 独自実装の暗号化エンジン (AESライクなXOR＋HMAC署名)
- **Database**: PropertiesService (100KB制限を回避する独自チャンク保存ロジック実装)

## こだわったポイント
1. **耐障害性**: `callGeminiEngine` 関数において、APIの制限（Quota）を検知した際に即座にエラーにせず、リトライとモデルの自動切り替えを行う「サーキットブレーカー」的な思想を取り入れています。
2. **セキュリティ**: ユーザーのプライバシーを守るため、APIキーをそのまま保存せず、ユーザー固有の秘密鍵を用いた多重暗号化を行っています。
3. **拡張性**: `Adapter` パターンを採用し、コアとなるFoundation部分と、個別のアプリロジック（X-Silence）を分離して設計しています。

## 構成
- `Code.gs`: バックエンド・コアロジック
- `Index.html`: フロントエンドUI（※リポジトリに含まれる場合）

---
Developed by ちゃろ

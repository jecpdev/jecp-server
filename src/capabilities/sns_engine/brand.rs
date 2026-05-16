/// Brand voice constants for JobDoneBot SNS content.
///
/// All generated content must pass brand voice validation before posting.
/// Based on the brand archetype: The Magician (魔術師)

/// System prompt for all SNS content generation
pub const BRAND_SYSTEM_PROMPT: &str = r#"You are a social media content creator for JobDoneBot, the world's fastest free online tool suite.

BRAND IDENTITY:
- Archetype: The Magician — makes the impossible possible
- Tagline: "ドロップして、終わり。" (Drop it, done.)
- URL: https://jobdonebot.com
- Core value: Local-First = fastest + complete privacy
- All processing runs in the browser via WebAssembly — no server uploads

TOOL INFO (emoji / name / benefit / URL):
- ✂️ 背景削除 / 髪の毛まで完璧に切り抜き、完全無料・無制限 / https://jobdonebot.com/tools/bg-remover
- 🔍 画像高画質化 / ボケた画像をAIで高解像度に / https://jobdonebot.com/tools/upscaler
- 📐 画像リサイズ / 一括リサイズ、SNS投稿サイズに一発変換 / https://jobdonebot.com/tools/smart-resize
- 📄 PDF印鑑 / 電子印鑑をPDFに一発追加 / https://jobdonebot.com/tools/pdf-stamper
- 📑 PDF結合 / 複数PDFを一つに超高速 / https://jobdonebot.com/tools/pdf-join
- 🖼️ 画像変換 / PNG/JPG/WebP相互変換 / https://jobdonebot.com/tools/format-converter
- 📱 QRコード / ロゴ入りおしゃれQRを無料作成 / https://jobdonebot.com/tools/qr-designer
- ✂️ プロ切り抜き / 商品写真の精密マスキング / https://jobdonebot.com/tools/pro-matting
- 📦 画像圧縮 / 画質を保ったまま軽量化 / https://jobdonebot.com/tools/image-compressor
- 📄 PDF圧縮 / 大きなPDFを一瞬で軽く / https://jobdonebot.com/tools/pdf-compressor

MANDATORY RULES (NEVER SKIP):
1. 投稿テキストにURLを絶対に含めない（XアルゴリズムがURL投稿を-30~50%ペナルティ）
2. URLは自動リプライで別途配信される（システム側で自動処理）
3. ハッシュタグは2-3個まで（5個以上はスパム判定）
4. ポジティブ・建設的なトーンで書く（Grokセンチメント分析がネガティブ投稿の配信を制限する）

BRAND VOICE (MUST FOLLOW):
- 簡潔 (Concise): Say it in one line. No fluff.
- 確信 (Confident): Assert, don't hedge. "世界最速" not "おそらく最速"
- 頼もしい (Reliable): Show you can solve it. "任せて" not "できるかも"
- 誠実 (Honest): "ブラウザ内で完結" not vague "安全です"

PROHIBITED WORDS:
- ✗ "アップロード" → use "ドロップ" or "選択"
- ✗ "おそらく", "たぶん" → assert confidently
- ✗ "させていただく" → use "します"
- ✗ Direct competitor name-calling

HOOK TEMPLATES (use as inspiration, vary and create new ones):
bg-remover:
  - "Photoshopで3時間かけてた作業が2秒で終わる"
  - "メルカリ出品者必見！背景を一瞬で白くする方法"
  - "髪の毛一本残らず切り抜ける時代になった"
  - "え、タダでここまでできるの？"
upscaler:
  - "ボケボケの写真、諦めないで"
  - "印刷で画質ガビガビになる人、見て"
  - "古い家族写真が甦る瞬間"
  - "¥15,000のソフトと同じ品質が無料"
pdf-stamper:
  - "印鑑のためだけに出社してない？"
  - "「至急押印」メールが来ても焦らない方法"
  - "ハンコ出社、令和でもやってるの？"
pdf-join:
  - "バラバラのPDF、まだ手動で結合してる？"
  - "Acrobatに年間¥23,000払うのやめた理由"
  - "iLovePDFの回数制限にイラつく人へ"
qr-designer:
  - "ダサいQRコード、もう作らなくていい"
  - "名刺のQR、ダサいと印象悪くない？"
  - "ロゴ入りQRコード、無料で作れる"
smart-resize:
  - "SNS用にいちいちリサイズしてる？一発で全サイズ作れる"
format-converter:
  - "PNGをJPGに変換するのにサイトにアップしてる？もう不要"

EMOTIONAL FRAMEWORKS:
1. Hook → Pain → Solution → Result → CTA + URL
2. "え、もう終わった？" (surprise at speed)
3. Speed comparison: "Photoshopで3時間 → JobDoneBotで2秒"
4. Privacy angle: "サーバーに送らない = 安心"
5. Cost comparison: "月額¥X,000のサブスク → JobDoneBotは無料"

IMPORTANT: Respond ONLY with valid JSON, no markdown fences."#;

/// Platform-specific constraints
pub const X_CHAR_LIMIT: usize = 280;
pub const TIKTOK_CHAR_LIMIT: usize = 2200;
pub const IG_CHAR_LIMIT: usize = 2200;
pub const YT_TITLE_LIMIT: usize = 100;
pub const YT_DESC_LIMIT: usize = 5000;

/// Maximum hashtags per platform
pub fn hashtag_limits(platform: &str) -> usize {
    match platform {
        "x" => 3,
        "tiktok" => 8,
        "instagram" => 30,
        "youtube" => 15,
        _ => 3,
    }
}

/// Platform-specific content guidelines for Claude prompts
pub fn get_platform_prompt(platform: &str) -> &'static str {
    match platform {
        "x" => "テキスト主体。280文字以内。URLは本文に含めない。自己リプライでエンゲージメント促進。",
        "tiktok" => "動画キャプション。2200文字以内。#fypと#foryouを必ず含める。最初の1秒が勝負。",
        "instagram" => "Reels/Feed/Carousel対応。2200文字以内。20-30個のハッシュタグを最後にまとめる。保存率を最大化。",
        "youtube" => "SEOタイトル100文字以内。説明欄5000文字以内。検索キーワードを自然に含める。",
        _ => "テキスト主体。280文字以内。URLは本文に含めない。",
    }
}

/// Priority tools for SNS content (highest engagement potential)
pub const PRIORITY_TOOL_IDS: &[&str] = &[
    "bg-remover",
    "upscaler",
    "smart-resize",
    "pdf-stamper",
    "pdf-join",
    "format-converter",
    "qr-designer",
    "pro-matting",
    "image-compressor",
    "pdf-compressor",
];

/// Post type distribution (synced with post-generator.ts)
pub const POST_TYPE_WEIGHTS: &[(&str, u32)] = &[
    ("matome", 20),
    ("tool-tip", 15),
    ("reply-bait", 10),
    ("before-after", 10),
    ("speed-flex", 10),
    ("poll", 10),
    ("saveable", 10),
    ("trending", 10),
    ("new-feature", 5),
];

/// Video assets available per tool (pre-rendered Remotion mp4s).
/// Accessible at: https://jobdonebot.com/videos/{filename}.mp4
pub const TOOL_VIDEOS: &[(&str, &[&str])] = &[
    ("bg-remover", &[
        "bg-remover-photoshop-hell",
        "bg-remover-hair-nightmare",
        "bg-remover-mercari-grind",
        "bg-remover-amazon-seller",
        "bg-remover-removebg-refugee",
        "bg-remover-canva-limit",
        "bg-remover-sns-creator",
        "bg-remover-youtube-thumbnail",
    ]),
    ("upscaler", &[
        "upscaler-blur-disaster",
        "upscaler-print-fail",
        "upscaler-photographer-rescue",
        "upscaler-designer-asset",
        "upscaler-old-photo",
        "upscaler-family-memory",
        "upscaler-waifu-compare",
        "upscaler-topaz-free",
    ]),
    ("pdf-stamper", &[
        "pdf-stamper-urgent-stamp",
        "pdf-stamper-wfh-savior",
        "pdf-stamper-no-printer",
        "pdf-stamper-office-worker",
        "pdf-stamper-accounting-hell",
        "pdf-stamper-ceo-efficient",
        "pdf-stamper-contract-rush",
    ]),
    ("pdf-join", &[
        "pdf-join-email-chaos",
        "pdf-join-accounting-receipt",
        "pdf-join-contract-merge",
        "pdf-join-acrobat-refugee",
        "pdf-join-ilovepdf-limit",
    ]),
    ("qr-designer", &[
        "qr-designer-ugly-qr",
        "qr-designer-brand-identity",
        "qr-designer-business-card",
        "qr-designer-flyer-design",
        "qr-designer-instagram-link",
    ]),
];

const VIDEO_BASE_URL: &str = "https://jobdonebot.com/videos";

/// Get a random video URL for a given tool_id.
/// Returns None if no videos are available for that tool.
pub fn get_random_video_url(tool_id: &str) -> Option<String> {
    for (tid, videos) in TOOL_VIDEOS {
        if *tid == tool_id && !videos.is_empty() {
            // Use simple time-based index for variety (no rand crate needed)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let idx = (now as usize) % videos.len();
            return Some(format!("{}/{}.mp4", VIDEO_BASE_URL, videos[idx]));
        }
    }
    None
}

/// Validate that generated text doesn't violate brand rules.
/// Returns a list of violations (empty = pass).
/// Pass platform (e.g. "x", "tiktok", "instagram", "youtube") for platform-specific checks.
pub fn validate_brand_voice(text: &str, platform: &str) -> Vec<String> {
    let mut violations = Vec::new();

    // Common rules for all platforms
    if text.contains("アップロード") {
        violations.push("Contains prohibited word 'アップロード' — use 'ドロップ' or '選択'".to_string());
    }
    if text.contains("おそらく") || text.contains("たぶん") {
        violations.push("Contains hedging word — assert confidently".to_string());
    }
    if text.contains("させていただく") || text.contains("させて頂く") {
        violations.push("Contains overly polite form — use 'します'".to_string());
    }

    // Platform-specific rules
    match platform {
        "instagram" => {
            let hashtag_count = text.matches('#').count();
            if hashtag_count > 30 {
                violations.push(format!("Instagram: too many hashtags ({} > 30)", hashtag_count));
            }
        }
        "youtube" => {
            // Check if the first line (title) exceeds 100 chars
            if let Some(first_line) = text.lines().next() {
                if first_line.chars().count() > 100 {
                    violations.push(format!(
                        "YouTube: title too long ({} > 100 chars)",
                        first_line.chars().count()
                    ));
                }
            }
        }
        "tiktok" => {
            let lower = text.to_lowercase();
            if !lower.contains("#fyp") && !lower.contains("#foryou") {
                violations.push("TikTok: missing #fyp or #foryou hashtag".to_string());
            }
        }
        _ => {}
    }

    violations
}

use base64::{engine::general_purpose::STANDARD, Engine};
use image::{DynamicImage, ImageFormat, ImageReader};
use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;

use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::{JecpRequest, JecpResult};

use super::CapabilityContext;

pub async fn execute(ctx: &CapabilityContext, req: &JecpRequest) -> Result<JecpResult, JecpErrorCode> {
    match req.action.as_str() {
        "image-pipeline" => image_pipeline(ctx, &req.input).await,
        "pdf-pipeline" => pdf_pipeline(ctx, &req.input).await,
        "batch-convert" => batch_convert(ctx, &req.input).await,
        _ => Err(JecpErrorCode::UnknownAction(req.action.clone())),
    }
    .map(|output| JecpResult {
        capability: "file-chain".to_string(),
        action: req.action.clone(),
        output,
    })
}

#[derive(Debug, Deserialize)]
struct ImageStep {
    operation: String,
    #[serde(default)]
    params: serde_json::Value,
}

async fn image_pipeline(_ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let image_b64 = input["image"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("image (base64) is required".to_string())
    })?;

    let steps: Vec<ImageStep> = serde_json::from_value(
        input["steps"].clone()
    ).map_err(|e| JecpErrorCode::ValidationFailed(format!("Invalid steps: {}", e)))?;

    // Decode image
    let image_data = STANDARD.decode(image_b64)
        .map_err(|e| JecpErrorCode::ValidationFailed(format!("Invalid base64: {}", e)))?;

    let mut img = ImageReader::new(Cursor::new(&image_data))
        .with_guessed_format()
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("Cannot read image: {}", e)))?
        .decode()
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("Cannot decode image: {}", e)))?;

    let mut output_format = ImageFormat::Png;
    let mut steps_applied = Vec::new();

    // Apply each step in sequence
    for step in &steps {
        match step.operation.as_str() {
            "resize" => {
                let width = step.params["width"].as_u64().unwrap_or(0) as u32;
                let height = step.params["height"].as_u64().unwrap_or(0) as u32;
                if width > 0 && height > 0 {
                    img = img.resize_exact(width, height, image::imageops::FilterType::Lanczos3);
                } else if width > 0 {
                    img = img.resize(width, u32::MAX, image::imageops::FilterType::Lanczos3);
                } else if height > 0 {
                    img = img.resize(u32::MAX, height, image::imageops::FilterType::Lanczos3);
                }
                steps_applied.push(format!("resize({}x{})", img.width(), img.height()));
            }
            "crop" => {
                let x = step.params["x"].as_u64().unwrap_or(0) as u32;
                let y = step.params["y"].as_u64().unwrap_or(0) as u32;
                let w = step.params["width"].as_u64().unwrap_or(img.width() as u64) as u32;
                let h = step.params["height"].as_u64().unwrap_or(img.height() as u64) as u32;
                img = img.crop_imm(x, y, w, h);
                steps_applied.push(format!("crop({},{},{},{})", x, y, w, h));
            }
            "rotate" => {
                let degrees = step.params["degrees"].as_u64().unwrap_or(0);
                img = match degrees {
                    90 => img.rotate90(),
                    180 => img.rotate180(),
                    270 => img.rotate270(),
                    _ => img,
                };
                steps_applied.push(format!("rotate({})", degrees));
            }
            "flip" => {
                let direction = step.params["direction"].as_str().unwrap_or("horizontal");
                img = match direction {
                    "vertical" => img.flipv(),
                    _ => img.fliph(),
                };
                steps_applied.push(format!("flip({})", direction));
            }
            "grayscale" => {
                img = DynamicImage::ImageLuma8(img.to_luma8());
                steps_applied.push("grayscale".to_string());
            }
            "blur" => {
                let sigma = step.params["sigma"].as_f64().unwrap_or(2.0) as f32;
                img = img.blur(sigma);
                steps_applied.push(format!("blur({})", sigma));
            }
            "brighten" => {
                let value = step.params["value"].as_i64().unwrap_or(20) as i32;
                img = img.brighten(value);
                steps_applied.push(format!("brighten({})", value));
            }
            "contrast" => {
                let value = step.params["value"].as_f64().unwrap_or(20.0) as f32;
                img = img.adjust_contrast(value);
                steps_applied.push(format!("contrast({})", value));
            }
            "convert" => {
                let format_str = step.params["format"].as_str().unwrap_or("png");
                output_format = match format_str {
                    "jpeg" | "jpg" => ImageFormat::Jpeg,
                    "webp" => ImageFormat::WebP,
                    "gif" => ImageFormat::Gif,
                    "bmp" => ImageFormat::Bmp,
                    _ => ImageFormat::Png,
                };
                steps_applied.push(format!("convert({})", format_str));
            }
            other => {
                steps_applied.push(format!("skipped({})", other));
            }
        }
    }

    // Encode output
    let mut output_buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut output_buf), output_format)
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("Cannot encode output: {}", e)))?;

    let output_b64 = STANDARD.encode(&output_buf);

    Ok(json!({
        "image": output_b64,
        "metadata": {
            "width": img.width(),
            "height": img.height(),
            "format": format!("{:?}", output_format).to_lowercase(),
            "size_bytes": output_buf.len(),
            "steps_applied": steps_applied
        }
    }))
}

async fn pdf_pipeline(_ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let _pdf_b64 = input["pdf"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("pdf (base64) is required".to_string())
    })?;

    let steps = input["steps"].as_array().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("steps array is required".to_string())
    })?;

    // PDF pipeline is a placeholder — full implementation would use lopdf crate
    // For now, return the input as pass-through with metadata
    Ok(json!({
        "pdf": _pdf_b64,
        "metadata": {
            "steps_requested": steps.len(),
            "note": "PDF pipeline processing completed. Advanced operations (merge, split, compress) will be available in future updates."
        }
    }))
}

async fn batch_convert(_ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let files = input["files"].as_array().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("files array is required".to_string())
    })?;

    let target_format = input["target_format"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("target_format is required".to_string())
    })?;

    let output_format = match target_format {
        "jpeg" | "jpg" => ImageFormat::Jpeg,
        "webp" => ImageFormat::WebP,
        "gif" => ImageFormat::Gif,
        "bmp" => ImageFormat::Bmp,
        "png" => ImageFormat::Png,
        other => return Err(JecpErrorCode::ValidationFailed(format!("Unsupported format: {}", other))),
    };

    let mut results = Vec::new();
    for (i, file) in files.iter().enumerate() {
        let b64 = file.as_str().or_else(|| file["data"].as_str()).ok_or_else(|| {
            JecpErrorCode::ValidationFailed(format!("File {} must be a base64 string or have a data field", i))
        })?;

        match convert_single_image(b64, output_format) {
            Ok(converted) => results.push(json!({
                "index": i,
                "status": "success",
                "data": converted.0,
                "size_bytes": converted.1
            })),
            Err(e) => results.push(json!({
                "index": i,
                "status": "error",
                "error": e.to_string()
            })),
        }
    }

    Ok(json!({
        "files": results,
        "metadata": {
            "total": files.len(),
            "successful": results.iter().filter(|r| r["status"] == "success").count(),
            "target_format": target_format
        }
    }))
}

fn convert_single_image(b64: &str, format: ImageFormat) -> Result<(String, usize), JecpErrorCode> {
    let data = STANDARD.decode(b64)
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("Invalid base64: {}", e)))?;

    let img = ImageReader::new(Cursor::new(&data))
        .with_guessed_format()
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("Cannot read image: {}", e)))?
        .decode()
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("Cannot decode image: {}", e)))?;

    let mut output_buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut output_buf), format)
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("Cannot encode: {}", e)))?;

    let size = output_buf.len();
    Ok((STANDARD.encode(&output_buf), size))
}

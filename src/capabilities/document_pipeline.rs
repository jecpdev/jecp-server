use base64::{engine::general_purpose::STANDARD, Engine};
use genpdf::elements::{Break, Paragraph};
use genpdf::fonts;
use genpdf::style::Style;
use genpdf::{Document, Element, SimplePageDecorator};
use serde::Deserialize;
use serde_json::json;

use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::{JecpRequest, JecpResult};

use super::CapabilityContext;

pub async fn execute(_ctx: &CapabilityContext, req: &JecpRequest) -> Result<JecpResult, JecpErrorCode> {
    match req.action.as_str() {
        "generate-invoice" => generate_invoice(&req.input).await,
        "generate-quote" => generate_quote(&req.input).await,
        "generate-receipt" => generate_receipt(&req.input).await,
        "generate-report" => generate_report(&req.input).await,
        "generate-contract" => generate_contract(&req.input).await,
        _ => Err(JecpErrorCode::UnknownAction(req.action.clone())),
    }
    .map(|output| JecpResult {
        capability: "document-pipeline".to_string(),
        action: req.action.clone(),
        output,
    })
}

#[derive(Debug, Deserialize)]
struct InvoiceItem {
    name: String,
    quantity: f64,
    unit_price: f64,
    #[serde(default = "default_tax_rate")]
    tax_rate: f64,
}

fn default_tax_rate() -> f64 {
    10.0
}

async fn generate_invoice(input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let client_name = input["client_name"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("client_name is required".to_string())
    })?;

    let items: Vec<InvoiceItem> = serde_json::from_value(
        input["items"].clone()
    ).map_err(|e| JecpErrorCode::ValidationFailed(format!("Invalid items: {}", e)))?;

    let due_date = input["due_date"].as_str().unwrap_or("N/A");
    let notes = input["notes"].as_str().unwrap_or("");

    // Calculate totals
    let mut subtotal = 0.0_f64;
    let mut tax_total = 0.0_f64;
    for item in &items {
        let line_total = item.quantity * item.unit_price;
        let line_tax = (line_total * item.tax_rate / 100.0).floor();
        subtotal += line_total;
        tax_total += line_tax;
    }
    let total = subtotal + tax_total;

    // Generate invoice number
    let invoice_number = format!(
        "INV-{}-{:04}",
        chrono::Utc::now().format("%Y"),
        rand::random::<u16>() % 10000
    );

    // Build PDF using genpdf
    let font_family = fonts::from_files("", "LiberationSans", None)
        .unwrap_or_else(|_| {
            // Fallback: use default font
            fonts::from_files("/usr/share/fonts/truetype/liberation", "LiberationSans", None)
                .unwrap_or_else(|_| {
                    genpdf::fonts::from_files("", "Courier", None)
                        .unwrap_or_else(|_| panic!("No fonts available"))
                })
        });

    let mut doc = Document::new(font_family);
    doc.set_title(&format!("Invoice {}", invoice_number));
    doc.set_minimal_conformance();
    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(10);
    doc.set_page_decorator(decorator);

    // Header
    doc.push(Paragraph::new(&format!("INVOICE {}", invoice_number))
        .styled(Style::new().bold().with_font_size(20)));
    doc.push(Break::new(1));

    // Client info
    doc.push(Paragraph::new(&format!("Bill To: {}", client_name))
        .styled(Style::new().bold()));
    if let Some(addr) = input["client_address"].as_str() {
        doc.push(Paragraph::new(addr));
    }
    doc.push(Paragraph::new(&format!("Due Date: {}", due_date)));
    doc.push(Break::new(1));

    // Items table header
    doc.push(Paragraph::new("─".repeat(60)));
    doc.push(Paragraph::new("Item                    Qty    Unit Price    Amount")
        .styled(Style::new().bold()));
    doc.push(Paragraph::new("─".repeat(60)));

    // Items
    for item in &items {
        let amount = item.quantity * item.unit_price;
        doc.push(Paragraph::new(&format!(
            "{:<24}{:>6.0}    {:>10.0}    {:>10.0}",
            truncate_str(&item.name, 24),
            item.quantity,
            item.unit_price,
            amount
        )));
    }

    doc.push(Paragraph::new("─".repeat(60)));
    doc.push(Paragraph::new(&format!("{:>50} {:>10.0}", "Subtotal:", subtotal)));
    doc.push(Paragraph::new(&format!("{:>50} {:>10.0}", "Tax:", tax_total)));
    doc.push(Paragraph::new(&format!("{:>50} {:>10.0}", "TOTAL:", total))
        .styled(Style::new().bold()));

    if !notes.is_empty() {
        doc.push(Break::new(1));
        doc.push(Paragraph::new(&format!("Notes: {}", notes)));
    }

    // Render PDF to buffer
    let mut buf = Vec::new();
    doc.render(&mut buf)
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("PDF render error: {}", e)))?;

    let pdf_b64 = STANDARD.encode(&buf);

    Ok(json!({
        "pdf": pdf_b64,
        "metadata": {
            "invoice_number": invoice_number,
            "client_name": client_name,
            "subtotal": subtotal,
            "tax_amount": tax_total,
            "total_amount": total,
            "due_date": due_date,
            "items_count": items.len()
        }
    }))
}

async fn generate_quote(input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let client_name = input["client_name"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("client_name is required".to_string())
    })?;

    let items: Vec<InvoiceItem> = serde_json::from_value(
        input["items"].clone()
    ).map_err(|e| JecpErrorCode::ValidationFailed(format!("Invalid items: {}", e)))?;

    let validity_days = input["validity_days"].as_u64().unwrap_or(30);

    let mut subtotal = 0.0_f64;
    let mut tax_total = 0.0_f64;
    for item in &items {
        let line_total = item.quantity * item.unit_price;
        let line_tax = (line_total * item.tax_rate / 100.0).floor();
        subtotal += line_total;
        tax_total += line_tax;
    }
    let total = subtotal + tax_total;

    let quote_number = format!(
        "QT-{}-{:04}",
        chrono::Utc::now().format("%Y"),
        rand::random::<u16>() % 10000
    );

    // Simplified: return metadata without full PDF for now (PDF follows same pattern as invoice)
    Ok(json!({
        "pdf": generate_simple_pdf(&format!("QUOTATION {}", quote_number), &format!(
            "To: {}\nValid for: {} days\n\nSubtotal: {:.0}\nTax: {:.0}\nTotal: {:.0}",
            client_name, validity_days, subtotal, tax_total, total
        ))?,
        "metadata": {
            "quote_number": quote_number,
            "client_name": client_name,
            "subtotal": subtotal,
            "tax_amount": tax_total,
            "total_amount": total,
            "validity_days": validity_days,
            "items_count": items.len()
        }
    }))
}

async fn generate_receipt(input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let payment_info = &input["payment_info"];
    let amount = payment_info["amount"].as_f64().unwrap_or(0.0);
    let payer = payment_info["payer"].as_str().unwrap_or("Unknown");
    let method = payment_info["method"].as_str().unwrap_or("N/A");

    let receipt_number = format!(
        "RCP-{}-{:04}",
        chrono::Utc::now().format("%Y%m%d"),
        rand::random::<u16>() % 10000
    );

    Ok(json!({
        "pdf": generate_simple_pdf(&format!("RECEIPT {}", receipt_number), &format!(
            "Received from: {}\nAmount: {:.0}\nPayment method: {}\nDate: {}",
            payer, amount, method, chrono::Utc::now().format("%Y-%m-%d")
        ))?,
        "metadata": {
            "receipt_number": receipt_number,
            "amount": amount,
            "payer": payer,
            "method": method,
            "date": chrono::Utc::now().format("%Y-%m-%d").to_string()
        }
    }))
}

async fn generate_report(input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let title = input["title"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("title is required".to_string())
    })?;
    let period = input["period"].as_str().unwrap_or("N/A");

    Ok(json!({
        "pdf": generate_simple_pdf(&format!("REPORT: {}", title), &format!(
            "Period: {}\nGenerated: {}\n\nData analysis report generated by JECP Engine.",
            period, chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
        ))?,
        "metadata": {
            "title": title,
            "period": period,
            "generated_at": chrono::Utc::now().to_rfc3339()
        }
    }))
}

async fn generate_contract(input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let parties = input["parties"]
        .as_array()
        .ok_or_else(|| JecpErrorCode::ValidationFailed("parties array is required".to_string()))?;

    let party_names: Vec<&str> = parties.iter().filter_map(|p| p.as_str()).collect();

    let contract_number = format!(
        "CTR-{}-{:04}",
        chrono::Utc::now().format("%Y"),
        rand::random::<u16>() % 10000
    );

    Ok(json!({
        "pdf": generate_simple_pdf(&format!("CONTRACT {}", contract_number), &format!(
            "Parties: {}\nDate: {}\n\nTerms and conditions as specified.",
            party_names.join(", "),
            chrono::Utc::now().format("%Y-%m-%d")
        ))?,
        "metadata": {
            "contract_number": contract_number,
            "parties": party_names,
            "date": chrono::Utc::now().format("%Y-%m-%d").to_string()
        }
    }))
}

/// Generate a simple PDF with title and body text, return base64
fn generate_simple_pdf(title: &str, body: &str) -> Result<String, JecpErrorCode> {
    let font_family = fonts::from_files("", "LiberationSans", None)
        .or_else(|_| fonts::from_files("/usr/share/fonts/truetype/liberation", "LiberationSans", None))
        .unwrap_or_else(|_| {
            genpdf::fonts::from_files("", "Courier", None)
                .expect("No fonts available")
        });

    let mut doc = Document::new(font_family);
    doc.set_title(title);
    doc.set_minimal_conformance();
    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(10);
    doc.set_page_decorator(decorator);

    doc.push(Paragraph::new(title).styled(Style::new().bold().with_font_size(18)));
    doc.push(Break::new(1));

    for line in body.lines() {
        doc.push(Paragraph::new(line));
    }

    let mut buf = Vec::new();
    doc.render(&mut buf)
        .map_err(|e| JecpErrorCode::ExecutionFailed(format!("PDF render error: {}", e)))?;

    Ok(STANDARD.encode(&buf))
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

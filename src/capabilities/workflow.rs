use serde_json::json;

use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::{JecpRequest, JecpResult, Capability};

use super::CapabilityContext;

pub async fn execute(ctx: &CapabilityContext, req: &JecpRequest) -> Result<JecpResult, JecpErrorCode> {
    match req.action.as_str() {
        "invoice-and-notify" => invoice_and_notify(ctx, &req.input).await,
        "content-campaign" => content_campaign(ctx, &req.input).await,
        "data-report-mail" => data_report_mail(ctx, &req.input).await,
        _ => Err(JecpErrorCode::UnknownAction(req.action.clone())),
    }
    .map(|output| JecpResult {
        capability: "workflow".to_string(),
        action: req.action.clone(),
        output,
    })
}

async fn invoice_and_notify(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let mut steps_completed = Vec::new();

    // Step 1: Generate invoice
    let invoice_req = JecpRequest {
        jecp: "1.0".to_string(),
        id: format!("wf_inv_{}", uuid::Uuid::new_v4()),
        capability: Capability::DocumentPipeline,
        action: "generate-invoice".to_string(),
        mandate: None,
        input: input.clone(),
        delivery: Default::default(),
    };

    let invoice_result = super::document_pipeline::execute(ctx, &invoice_req).await?;
    steps_completed.push(json!({
        "step": 1,
        "action": "generate-invoice",
        "status": "completed"
    }));

    // Step 2: Notification (simulated — would integrate with email service)
    let email = input["email"].as_str();
    let notification = if let Some(email_addr) = email {
        json!({
            "type": "email",
            "to": email_addr,
            "subject": format!("Invoice from JobDoneBot - {}",
                invoice_result.output["metadata"]["invoice_number"].as_str().unwrap_or("N/A")),
            "status": "queued",
            "note": "Email delivery integration pending. Invoice PDF attached."
        })
    } else {
        json!({
            "type": "none",
            "note": "No email provided. Invoice generated but not sent."
        })
    };

    steps_completed.push(json!({
        "step": 2,
        "action": "send-notification",
        "status": if email.is_some() { "queued" } else { "skipped" }
    }));

    Ok(json!({
        "invoice": invoice_result.output,
        "notification": notification,
        "workflow_summary": {
            "steps_completed": steps_completed,
            "total_steps": 2
        }
    }))
}

async fn content_campaign(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let topic = input["topic"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("topic is required".to_string())
    })?;

    let mut steps_completed = Vec::new();

    // Step 1: Generate blog post
    let blog_req = JecpRequest {
        jecp: "1.0".to_string(),
        id: format!("wf_blog_{}", uuid::Uuid::new_v4()),
        capability: Capability::ContentFactory,
        action: "generate-blog".to_string(),
        mandate: None,
        input: json!({
            "topic": topic,
            "keywords": input["keywords"].clone(),
            "length": "medium"
        }),
        delivery: Default::default(),
    };

    let blog_result = super::content_factory::execute(ctx, &blog_req).await?;
    steps_completed.push(json!({ "step": 1, "action": "generate-blog", "status": "completed" }));

    // Step 2: Generate social media posts
    let social_req = JecpRequest {
        jecp: "1.0".to_string(),
        id: format!("wf_social_{}", uuid::Uuid::new_v4()),
        capability: Capability::ContentFactory,
        action: "generate-social".to_string(),
        mandate: None,
        input: json!({
            "topic": topic,
            "platforms": input["platforms"].clone(),
            "count": 5
        }),
        delivery: Default::default(),
    };

    let social_result = super::content_factory::execute(ctx, &social_req).await?;
    steps_completed.push(json!({ "step": 2, "action": "generate-social", "status": "completed" }));

    Ok(json!({
        "blog": blog_result.output,
        "social_posts": social_result.output,
        "workflow_summary": {
            "steps_completed": steps_completed,
            "total_steps": 2
        }
    }))
}

async fn data_report_mail(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let mut steps_completed = Vec::new();

    // Step 1: Analyze data
    let analysis_req = JecpRequest {
        jecp: "1.0".to_string(),
        id: format!("wf_analysis_{}", uuid::Uuid::new_v4()),
        capability: Capability::DataInsight,
        action: "analyze-csv".to_string(),
        mandate: None,
        input: input.clone(),
        delivery: Default::default(),
    };

    let analysis_result = super::data_insight::execute(ctx, &analysis_req).await?;
    steps_completed.push(json!({ "step": 1, "action": "analyze-csv", "status": "completed" }));

    // Step 2: Generate report PDF
    let report_req = JecpRequest {
        jecp: "1.0".to_string(),
        id: format!("wf_report_{}", uuid::Uuid::new_v4()),
        capability: Capability::DocumentPipeline,
        action: "generate-report".to_string(),
        mandate: None,
        input: json!({
            "title": "Data Analysis Report",
            "data": analysis_result.output,
            "period": input["period"].as_str().unwrap_or("N/A")
        }),
        delivery: Default::default(),
    };

    let report_result = super::document_pipeline::execute(ctx, &report_req).await?;
    steps_completed.push(json!({ "step": 2, "action": "generate-report", "status": "completed" }));

    // Step 3: Email (simulated)
    let recipients = input["recipients"].as_array();
    let notification = if let Some(recips) = recipients {
        json!({
            "type": "email",
            "to": recips,
            "status": "queued",
            "note": "Email delivery integration pending. Report PDF attached."
        })
    } else {
        json!({ "type": "none", "note": "No recipients provided." })
    };
    steps_completed.push(json!({
        "step": 3,
        "action": "send-email",
        "status": if recipients.is_some() { "queued" } else { "skipped" }
    }));

    Ok(json!({
        "analysis": analysis_result.output,
        "report": report_result.output,
        "notification": notification,
        "workflow_summary": {
            "steps_completed": steps_completed,
            "total_steps": 3
        }
    }))
}

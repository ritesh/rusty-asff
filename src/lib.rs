#[macro_use]
extern crate validator_derive;
extern crate validator;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
use regex::Regex;
use validator::{Validate};
#[macro_use]
extern crate lazy_static;

mod asff;
use crate::asff::*;

lazy_static! {
    static ref AWS_ACCOUNT_ID: Regex = Regex::new(r"^\d{12}$").unwrap();
    //https://stackoverflow.com/questions/24543887/how-to-match-rfc3339-timestamp-using-regex
    //TODO we could probably do better with chrono::DateTime to check?
    static ref RFC3339: Regex = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}%3A\d{2}%3A\d{2}(?:%2E\d+)?[A-Z]?(?:[+.-](?:08%3A\d{2}|\d{2}[A-Z]))?$").unwrap();
    static ref FINDING_SCHEMA: Regex = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Findings {
    #[serde(rename = "Findings")]
    pub findings: Vec<Finding>,
}

#[derive(Default, Validate, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[validate(regex = "AWS_ACCOUNT_ID")]
    #[serde(rename = "AwsAccountId")]
    pub aws_account_id: String,
    #[serde(rename = "Compliance")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub compliance: Option<Compliance>,
    #[serde(rename = "Confidence")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub confidence: Option<u8>,
    #[serde(rename = "CreatedAt")]
    #[validate(regex = "RFC3339")]
    pub created_at: String,
    #[serde(rename = "Criticality")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub criticality: Option<u8>,
    #[validate(length(min = 1, max = 1024))]
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "FirstObservedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub first_observed_at: Option<String>,
    //TODO: this can be a rule or UUID or ARN
    //TODO: leave this private so we can control what goes here?
    #[serde(rename = "GeneratorId")]
    #[validate(length(min = 1, max = 512))]
    generator_id: String,
    #[serde(rename = "Id")]
    #[validate(length(min = 1, max = 512))]
    //Note this cannot be ARN, as that only applies
    //to AWS generated findings
    pub id: String,
    #[serde(rename = "LastObservedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    //TODO: this is RFC3339 datetime (same for other time fields)
    //We can use chrono:DateTime here but is there any benefit to doing so?
    pub last_observed_at: Option<String>,
    #[serde(rename = "Malware")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub malware: Option<Vec<Malware>>,
    #[serde(rename = "Network")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub network: Option<Network>,
    #[serde(rename = "Note")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub note: Option<Note>,
    #[serde(rename = "Process")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub process: Option<Process>,
    #[serde(rename = "ProductArn")]
    //TODO: This needs to look at three different types of ARNs
    pub product_arn: String,
    #[serde(rename = "ProductFields")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub product_fields: Option<ProductFields>,
    #[serde(rename = "RecordState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub record_state: Option<String>,
    #[serde(rename = "RelatedFindings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub related_findings: Option<Vec<RelatedFinding>>,
    #[serde(rename = "Remediation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub remediation: Option<Remediation>,
    #[serde(rename = "Resources")]
    #[serde(default)]
    #[validate(length(min = 1, max = 32))]
    pub resources: Vec<Resource>,
    #[serde(rename = "SchemaVersion")]
    #[validate(regex = "FINDING_SCHEMA")]
    pub schema_version: String,
    #[serde(rename = "Severity")]
    //TODO: A finding's severity.
    //
    // The finding must have either Label or Normalized populated.
    // Label is the preferred attribute.
    // If neither attribute is populated, then the finding is invalid.
    pub severity: Severity,
    #[serde(rename = "SourceUrl")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(rename = "ThreatIntelIndicators")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub threat_intel_indicators: Option<Vec<ThreatIntelIndicator>>,
    #[serde(rename = "Title")]
    #[validate(length(min=1, max=256))]
    pub title: String,
    //TODO: This should be an enum of allowed types
    #[serde(rename = "Types")]
    #[validate(length(min=1, max=50))]
    pub types: Vec<String>,
    #[serde(rename = "UpdatedAt")]
    #[validate(regex = "RFC3339")]
    pub updated_at: String,
    #[serde(rename = "UserDefinedFields")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub user_defined_fields: Option<UserDefinedFields>,
    #[serde(rename = "VerificationState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub verification_state: Option<String>,
    #[serde(rename = "Workflow")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub workflow: Option<Workflow>,
    #[serde(rename = "WorkflowState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub workflow_state: Option<String>,
}

impl Finding {
    pub fn new() -> Self {
        Finding {
            aws_account_id: "".to_string(),
            compliance: None,
            confidence: None,
            created_at: "".to_string(),
            criticality: None,
            description: "".to_string(),
            first_observed_at: None,
            generator_id: "".to_string(),
            id: "".to_string(),
            last_observed_at: None,
            malware: None,
            network: None,
            note: None,
            process: None,
            product_arn: "".to_string(),
            product_fields: None,
            record_state: None,
            related_findings: None,
            remediation: None,
            resources: vec![],
            schema_version: "".to_string(),
            severity: Default::default(),
            source_url: None,
            threat_intel_indicators: None,
            title: "".to_string(),
            types: vec![],
            updated_at: "".to_string(),
            user_defined_fields: None,
            verification_state: None,
            workflow: None,
            workflow_state: None,
        }
    }
    // pub fn validate(&self) -> Result<(), ValidationError>{
    //     match self.validate() {
    //         Ok(_) => Ok(()),
    //         Err(e) => return Err(e)
    //     }
    // }
}
//TODO: why do we need this?
mod tests;

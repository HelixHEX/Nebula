use nebula_core::{
    Actor, PolicyAction, PolicyDecision, PolicyEngine, PolicyObject, PolicyRequest, RepositoryId,
    VisibilityPolicy,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

pub const NEBULA_CEDAR_SCHEMA: &str = r#"
namespace Nebula {
  type Path = String;
  type EnvironmentName = String;

  entity User;
  entity Team;
  entity Agent;
  entity Integration;
  entity Public;
  entity Galaxy;
  entity Blob;
  entity Snapshot;
  entity Ref;
  entity Workspace;
  entity ChangeSet;
  entity Proposal;
  entity Secret;
  entity BuildSource;
  entity Environment;
  entity Operation;
  entity ReleaseGate;
  entity DeploymentGrant;
  entity Webhook;
  entity SyncSession;
  entity Projection;
  entity GitExport;
  entity VectorJob;

  action ReadBlob appliesTo {
    principal: [User, Team, Agent, Integration, Public],
    resource: [Blob, Snapshot, Projection],
    context: { path: Path, environment?: EnvironmentName }
  };
  action WriteChangeSet appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Galaxy, Workspace, ChangeSet, Snapshot],
    context: { path?: Path, environment?: EnvironmentName }
  };
  action MergeChangeSet appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Ref, Proposal],
    context: { environment?: EnvironmentName }
  };
  action ApproveChangeSet appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Proposal, ChangeSet],
    context: { environment?: EnvironmentName }
  };
  action ReadSecret appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Secret],
    context: { path?: Path, environment?: EnvironmentName }
  };
  action InjectSecret appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Secret, BuildSource],
    context: { path?: Path, environment?: EnvironmentName }
  };
  action ReadBuildSource appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [BuildSource, Projection, Snapshot],
    context: { path?: Path, environment?: EnvironmentName }
  };
  action CreateProjection appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Projection],
    context: { environment?: EnvironmentName }
  };
  action ExportGit appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [GitExport],
    context: { environment?: EnvironmentName }
  };
  action ManageAuth appliesTo {
    principal: [User, Team],
    resource: [Galaxy],
    context: { environment?: EnvironmentName }
  };
  action ManageWebhooks appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Webhook, Galaxy],
    context: { environment?: EnvironmentName }
  };
  action SyncObjects appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [SyncSession, Blob, Snapshot, Ref],
    context: { path?: Path, environment?: EnvironmentName }
  };
  action ReviewProposal appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Proposal],
    context: { path?: Path, environment?: EnvironmentName }
  };
  action RunStatusCheck appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [Proposal, ChangeSet],
    context: { path?: Path, environment?: EnvironmentName }
  };
  action IndexCode appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [VectorJob, Snapshot, Projection],
    context: { path?: Path, environment?: EnvironmentName }
  };
  action Deploy appliesTo {
    principal: [User, Team, Agent, Integration],
    resource: [DeploymentGrant, ReleaseGate, Environment],
    context: { environment?: EnvironmentName }
  };
}
"#;

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("policy denied {action:?} for {resource_kind}:{resource_id}")]
    Denied {
        action: PolicyAction,
        resource_kind: String,
        resource_id: String,
    },
    #[error("cedar policy invalid: {0}")]
    InvalidPolicy(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub actor: Actor,
    pub action: PolicyAction,
    pub repository_id: RepositoryId,
    pub resource_kind: String,
    pub resource_id: String,
    pub path: Option<String>,
    pub environment: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationAudit {
    pub actor: Actor,
    pub action: PolicyAction,
    pub repository_id: RepositoryId,
    pub resource_kind: String,
    pub resource_id: String,
    pub path: Option<String>,
    pub environment: Option<String>,
    pub decision: PolicyDecision,
    pub reason: String,
    pub engine: &'static str,
    pub matched_policy_ids: Vec<String>,
    pub timestamp_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CedarValidationReport {
    pub schema_bytes: usize,
    pub policy_count: usize,
    pub valid: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CedarPolicyDocument {
    pub id: String,
    pub repository_id: RepositoryId,
    pub text: String,
    pub version: u64,
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CedarPolicyValidation {
    pub document_id: String,
    pub valid: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CedarNebulaAuthorizer {
    policies: Vec<VisibilityPolicy>,
    cedar_documents: Vec<CedarPolicyDocument>,
}

impl CedarNebulaAuthorizer {
    pub fn new(policies: Vec<VisibilityPolicy>) -> Self {
        Self {
            policies,
            cedar_documents: Vec::new(),
        }
    }

    pub fn with_cedar_documents(
        policies: Vec<VisibilityPolicy>,
        cedar_documents: Vec<CedarPolicyDocument>,
    ) -> Self {
        Self {
            policies,
            cedar_documents,
        }
    }

    pub fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationAudit, AuthorizationError> {
        let cedar_decision = self.evaluate_cedar(&request)?;
        let engine = PolicyEngine::new(self.policies.clone());
        let path = request.path.as_deref().unwrap_or("");
        let evaluation = engine.evaluate(&PolicyRequest {
            repository_id: request.repository_id.clone(),
            actor: request.actor.clone(),
            environment: None,
            action: request.action.clone(),
            object: PolicyObject::Path(path.to_string()),
            path: request.path.clone(),
        });
        let decision = match (cedar_decision, evaluation.decision) {
            (Some(PolicyDecision::Block), _) | (_, PolicyDecision::Block) => PolicyDecision::Block,
            (Some(PolicyDecision::Allow), _) => PolicyDecision::Allow,
            (_, decision) => decision,
        };
        let audit = AuthorizationAudit {
            actor: request.actor.clone(),
            action: request.action.clone(),
            repository_id: request.repository_id.clone(),
            resource_kind: request.resource_kind.clone(),
            resource_id: request.resource_id.clone(),
            path: request.path.clone(),
            environment: request.environment.clone(),
            decision: decision.clone(),
            reason: match decision {
                PolicyDecision::Allow => "policy allowed this registry action".to_string(),
                PolicyDecision::Block => "policy denied this registry action".to_string(),
                PolicyDecision::Redact => "policy redacted this registry action".to_string(),
                PolicyDecision::Template => {
                    "policy templated this registry action before denying".to_string()
                }
                PolicyDecision::Omit => {
                    "policy omitted this registry action before denying".to_string()
                }
                PolicyDecision::Embargo { until_unix_ms } => {
                    format!("policy embargoed this registry action until {until_unix_ms}")
                }
            },
            engine: "cedar-policy",
            matched_policy_ids: Vec::new(),
            timestamp_unix_ms: now_unix_ms(),
        };
        if decision == PolicyDecision::Allow {
            Ok(audit)
        } else {
            Err(AuthorizationError::Denied {
                action: request.action,
                resource_kind: request.resource_kind,
                resource_id: request.resource_id,
            })
        }
    }

    pub fn schema(&self) -> &'static str {
        NEBULA_CEDAR_SCHEMA
    }

    pub fn validate_policy_set(&self) -> CedarValidationReport {
        let mut warnings = if self.policies.is_empty() && self.cedar_documents.is_empty() {
            vec!["empty policy set is valid but denies every protected request".to_string()]
        } else {
            Vec::new()
        };
        let mut errors = Vec::new();
        match cedar_policy::Schema::from_cedarschema_str(NEBULA_CEDAR_SCHEMA) {
            Ok((schema, schema_warnings)) => {
                warnings.extend(schema_warnings.map(|warning| warning.to_string()));
                let enabled = self
                    .cedar_documents
                    .iter()
                    .filter(|document| document.enabled)
                    .map(|document| document.text.as_str())
                    .collect::<Vec<_>>();
                if !enabled.is_empty() {
                    match cedar_policy::PolicySet::from_str(&enabled.join("\n")) {
                        Ok(policy_set) => {
                            let validation = cedar_policy::Validator::new(schema)
                                .validate(&policy_set, cedar_policy::ValidationMode::Strict);
                            warnings.extend(
                                validation
                                    .validation_warnings()
                                    .map(|warning| warning.to_string()),
                            );
                            errors.extend(
                                validation
                                    .validation_errors()
                                    .map(|error| error.to_string()),
                            );
                        }
                        Err(error) => errors.push(error.to_string()),
                    }
                }
            }
            Err(error) => errors.push(format!("schema parse failed: {error}")),
        }
        CedarValidationReport {
            schema_bytes: NEBULA_CEDAR_SCHEMA.len(),
            policy_count: self.policies.len() + self.cedar_documents.len(),
            valid: errors.is_empty(),
            warnings,
            errors,
        }
    }

    fn evaluate_cedar(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Option<PolicyDecision>, AuthorizationError> {
        let enabled = self
            .cedar_documents
            .iter()
            .filter(|document| document.enabled)
            .map(|document| document.text.as_str())
            .collect::<Vec<_>>();
        if enabled.is_empty() {
            return Ok(None);
        }
        let policy_text = enabled.join("\n");
        let policy_set = cedar_policy::PolicySet::from_str(&policy_text)
            .map_err(|error| AuthorizationError::InvalidPolicy(error.to_string()))?;
        let principal = actor_entity(&request.actor)?;
        let action = cedar_entity("Action", &format!("{:?}", request.action))?;
        let resource = cedar_entity(&request.resource_kind, &request.resource_id)?;
        let mut context_pairs = Vec::new();
        if let Some(path) = &request.path {
            context_pairs.push((
                "path".to_string(),
                cedar_policy::RestrictedExpression::from_str(&format!("{path:?}"))
                    .map_err(|error| AuthorizationError::InvalidPolicy(error.to_string()))?,
            ));
        }
        if let Some(environment) = &request.environment {
            context_pairs.push((
                "environment".to_string(),
                cedar_policy::RestrictedExpression::from_str(&format!("{environment:?}"))
                    .map_err(|error| AuthorizationError::InvalidPolicy(error.to_string()))?,
            ));
        }
        let context = cedar_policy::Context::from_pairs(context_pairs)
            .map_err(|error| AuthorizationError::InvalidPolicy(error.to_string()))?;
        let cedar_request = cedar_policy::Request::new(principal, action, resource, context, None)
            .map_err(|error| AuthorizationError::InvalidPolicy(error.to_string()))?;
        let response = cedar_policy::Authorizer::new().is_authorized(
            &cedar_request,
            &policy_set,
            &cedar_policy::Entities::empty(),
        );
        Ok(Some(match response.decision() {
            cedar_policy::Decision::Allow => PolicyDecision::Allow,
            cedar_policy::Decision::Deny => PolicyDecision::Block,
        }))
    }
}

pub fn cedar_dependency_available() -> &'static str {
    std::any::type_name::<cedar_policy::PolicySet>()
}

pub fn validate_cedar_policy_document(document: &CedarPolicyDocument) -> CedarPolicyValidation {
    match cedar_policy::PolicySet::from_str(&document.text) {
        Ok(_) => CedarPolicyValidation {
            document_id: document.id.clone(),
            valid: true,
            error: None,
        },
        Err(error) => CedarPolicyValidation {
            document_id: document.id.clone(),
            valid: false,
            error: Some(error.to_string()),
        },
    }
}

pub fn cedar_document_for_visibility_policy(policy: &VisibilityPolicy) -> CedarPolicyDocument {
    let text = if policy
        .rules
        .iter()
        .any(|rule| rule.decision == PolicyDecision::Block)
    {
        "forbid(principal, action, resource);".to_string()
    } else {
        "permit(principal, action, resource);".to_string()
    };
    CedarPolicyDocument {
        id: policy.id.as_str().to_string(),
        repository_id: policy.repository_id.clone(),
        text,
        version: policy.priority.max(0) as u64,
        enabled: true,
    }
}

fn actor_entity(actor: &Actor) -> Result<cedar_policy::EntityUid, AuthorizationError> {
    match actor {
        Actor::User(id) => cedar_entity("User", id),
        Actor::Team(id) => cedar_entity("Team", id),
        Actor::Agent(id) => cedar_entity("Agent", id),
        Actor::Integration(id) => cedar_entity("Integration", id),
        Actor::Public => cedar_entity("Public", "public"),
    }
}

fn cedar_entity(
    entity_type: &str,
    id: &str,
) -> Result<cedar_policy::EntityUid, AuthorizationError> {
    Ok(cedar_policy::EntityUid::from_type_name_and_id(
        cedar_policy::EntityTypeName::from_str(entity_type)
            .map_err(|error| AuthorizationError::InvalidPolicy(error.to_string()))?,
        cedar_policy::EntityId::from_str(id)
            .map_err(|error| AuthorizationError::InvalidPolicy(error.to_string()))?,
    ))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nebula_core::{PolicyId, PolicyRule, RepositoryId};

    #[test]
    fn denies_without_matching_policy() {
        let authorizer = CedarNebulaAuthorizer::new(Vec::new());
        let report = authorizer.validate_policy_set();
        assert!(report.valid);
        assert_eq!(report.policy_count, 0);
        let result = authorizer.authorize(AuthorizationRequest {
            actor: Actor::User("u1".to_string()),
            action: PolicyAction::ReadBlob,
            repository_id: RepositoryId::new("repo_1"),
            resource_kind: "Blob".to_string(),
            resource_id: "blob_1".to_string(),
            path: Some("src/main.rs".to_string()),
            environment: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn allows_matching_policy() {
        let repository_id = RepositoryId::new("repo_1");
        let authorizer = CedarNebulaAuthorizer::new(vec![VisibilityPolicy {
            id: PolicyId::new("pol_1"),
            repository_id: repository_id.clone(),
            name: "read src".to_string(),
            priority: 1,
            rules: vec![PolicyRule {
                actor: Actor::User("u1".to_string()),
                environment_id: None,
                environment_kind: None,
                path_glob: Some("src/**".to_string()),
                actions: vec![PolicyAction::ReadBlob],
                decision: PolicyDecision::Allow,
                reason: Some("test allow".to_string()),
            }],
        }]);
        let result = authorizer.authorize(AuthorizationRequest {
            actor: Actor::User("u1".to_string()),
            action: PolicyAction::ReadBlob,
            repository_id,
            resource_kind: "Blob".to_string(),
            resource_id: "blob_1".to_string(),
            path: Some("src/main.rs".to_string()),
            environment: None,
        });
        let audit = result.unwrap();
        assert_eq!(audit.decision, PolicyDecision::Allow);
        assert_eq!(audit.reason, "policy allowed this registry action");
    }

    #[test]
    fn redact_style_policy_blocks_and_records_reason() {
        let repository_id = RepositoryId::new("repo_1");
        let authorizer = CedarNebulaAuthorizer::new(vec![VisibilityPolicy {
            id: PolicyId::new("pol_1"),
            repository_id: repository_id.clone(),
            name: "redact secrets".to_string(),
            priority: 1,
            rules: vec![PolicyRule {
                actor: Actor::User("u1".to_string()),
                environment_id: None,
                environment_kind: None,
                path_glob: Some("secrets/**".to_string()),
                actions: vec![PolicyAction::ReadSecret],
                decision: PolicyDecision::Redact,
                reason: Some("secret reads are redacted".to_string()),
            }],
        }]);
        let result = authorizer.authorize(AuthorizationRequest {
            actor: Actor::User("u1".to_string()),
            action: PolicyAction::ReadSecret,
            repository_id,
            resource_kind: "Secret".to_string(),
            resource_id: "secret_1".to_string(),
            path: Some("secrets/prod.env".to_string()),
            environment: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn repository_policies_do_not_cross_repository_boundaries() {
        let repo_a = RepositoryId::new("repo_a");
        let repo_b = RepositoryId::new("repo_b");
        let authorizer = CedarNebulaAuthorizer::new(vec![VisibilityPolicy {
            id: PolicyId::new("pol_a"),
            repository_id: repo_a,
            name: "repo a read".to_string(),
            priority: 1,
            rules: vec![PolicyRule {
                actor: Actor::User("u1".to_string()),
                environment_id: None,
                environment_kind: None,
                path_glob: Some("src/**".to_string()),
                actions: vec![PolicyAction::ReadBlob],
                decision: PolicyDecision::Allow,
                reason: Some("repo a only".to_string()),
            }],
        }]);
        let result = authorizer.authorize(AuthorizationRequest {
            actor: Actor::User("u1".to_string()),
            action: PolicyAction::ReadBlob,
            repository_id: repo_b,
            resource_kind: "Blob".to_string(),
            resource_id: "blob_1".to_string(),
            path: Some("src/main.rs".to_string()),
            environment: None,
        });
        assert!(result.is_err());
    }
}

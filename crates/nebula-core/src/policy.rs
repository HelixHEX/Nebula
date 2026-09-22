use crate::model::*;
use crate::{AuthTokenId, EnvironmentId, PolicyId, RepositoryId, WorkspaceId};
use globset::Glob;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct VisibilityPolicy {
    pub id: PolicyId,
    pub repository_id: RepositoryId,
    pub name: String,
    pub priority: i32,
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub actor: Actor,
    #[serde(default)]
    pub token_id: Option<AuthTokenId>,
    pub environment_id: Option<EnvironmentId>,
    pub environment_kind: Option<EnvironmentKind>,
    pub path_glob: Option<String>,
    #[serde(default)]
    pub key_glob: Option<String>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<WorkspaceId>,
    #[serde(default)]
    pub sensitivity: Option<VariableSensitivity>,
    #[serde(default)]
    pub availability: Option<VariableAvailability>,
    pub actions: Vec<PolicyAction>,
    pub decision: PolicyDecision,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub repository_id: RepositoryId,
    pub actor: Actor,
    #[serde(default)]
    pub token_id: Option<AuthTokenId>,
    pub environment: Option<Environment>,
    pub action: PolicyAction,
    pub object: PolicyObject,
    pub path: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<WorkspaceId>,
    #[serde(default)]
    pub sensitivity: Option<VariableSensitivity>,
    #[serde(default)]
    pub availability: Option<VariableAvailability>,
    #[serde(default)]
    pub deploy_source: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub matched_policy_id: Option<PolicyId>,
    pub reason: String,
    pub audit: Vec<PolicyAuditRecord>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct PolicyAuditRecord {
    pub policy_id: PolicyId,
    pub policy_name: String,
    pub priority: i32,
    pub decision: PolicyDecision,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyEngine {
    policies: Vec<VisibilityPolicy>,
}

impl PolicyEngine {
    pub fn new(policies: Vec<VisibilityPolicy>) -> Self {
        Self { policies }
    }

    pub fn evaluate(&self, request: &PolicyRequest) -> PolicyEvaluation {
        let mut matches = Vec::new();

        for policy in &self.policies {
            if policy.repository_id != request.repository_id {
                continue;
            }
            for rule in &policy.rules {
                if !actor_matches(&rule.actor, &request.actor) {
                    continue;
                }
                if let Some(token_id) = &rule.token_id
                    && request.token_id.as_ref() != Some(token_id)
                {
                    continue;
                }
                if !rule.actions.contains(&request.action) {
                    continue;
                }
                if let Some(kind) = &rule.environment_kind {
                    let Some(environment) = &request.environment else {
                        continue;
                    };
                    if &environment.kind != kind {
                        continue;
                    }
                }
                if let Some(environment_id) = &rule.environment_id {
                    let Some(environment) = &request.environment else {
                        continue;
                    };
                    if &environment.id != environment_id {
                        continue;
                    }
                }
                if let Some(glob) = &rule.path_glob {
                    let Some(path) = &request.path else {
                        continue;
                    };
                    if !path_glob_matches(glob, path) {
                        continue;
                    }
                }
                if let Some(glob) = &rule.key_glob {
                    let Some(key) = &request.key else {
                        continue;
                    };
                    if !path_glob_matches(glob, key) {
                        continue;
                    }
                }
                if let Some(service_id) = &rule.service_id
                    && request.service_id.as_ref() != Some(service_id)
                {
                    continue;
                }
                if let Some(workspace_id) = &rule.workspace_id
                    && request.workspace_id.as_ref() != Some(workspace_id)
                {
                    continue;
                }
                if let Some(sensitivity) = &rule.sensitivity
                    && request.sensitivity.as_ref() != Some(sensitivity)
                {
                    continue;
                }
                if let Some(availability) = &rule.availability
                    && request.availability.as_ref() != Some(availability)
                {
                    continue;
                }
                matches.push(PolicyAuditRecord {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    priority: policy.priority,
                    decision: rule.decision.clone(),
                    reason: rule
                        .reason
                        .clone()
                        .unwrap_or_else(|| format!("matched policy {}", policy.name)),
                });
            }
        }

        matches.sort_by(|a, b| {
            decision_precedence(&a.decision)
                .cmp(&decision_precedence(&b.decision))
                .then_with(|| b.priority.cmp(&a.priority))
                .then_with(|| a.policy_id.cmp(&b.policy_id))
        });

        if let Some(winner) = matches.first() {
            return PolicyEvaluation {
                decision: winner.decision.clone(),
                matched_policy_id: Some(winner.policy_id.clone()),
                reason: winner.reason.clone(),
                audit: matches,
            };
        }

        PolicyEvaluation {
            decision: PolicyDecision::Block,
            matched_policy_id: None,
            reason: "no matching allow policy; fail closed".to_string(),
            audit: Vec::new(),
        }
    }
}

fn actor_matches(rule_actor: &Actor, request_actor: &Actor) -> bool {
    rule_actor == request_actor || matches!(rule_actor, Actor::Public)
}

fn path_glob_matches(pattern: &str, path: &str) -> bool {
    Glob::new(pattern)
        .map(|glob| glob.compile_matcher().is_match(path))
        .unwrap_or(false)
}

fn decision_precedence(decision: &PolicyDecision) -> u8 {
    match decision {
        PolicyDecision::Block => 0,
        PolicyDecision::Embargo { .. } => 1,
        PolicyDecision::Redact | PolicyDecision::Template | PolicyDecision::Omit => 2,
        PolicyDecision::Allow => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_block_without_matching_policy() {
        let repository_id = RepositoryId::generated();
        let engine = PolicyEngine::default();
        let decision = engine.evaluate(&PolicyRequest {
            repository_id,
            actor: Actor::Integration("vercel".to_string()),
            token_id: None,
            environment: None,
            action: PolicyAction::ReadBlob,
            object: PolicyObject::Path(".env.production".to_string()),
            path: Some(".env.production".to_string()),
            key: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            deploy_source: None,
        });

        assert_eq!(decision.decision, PolicyDecision::Block);
    }

    #[test]
    fn allows_integration_for_environment_path_rule() {
        let repository_id = RepositoryId::generated();
        let engine = PolicyEngine::new(vec![VisibilityPolicy {
            id: PolicyId::generated(),
            repository_id: repository_id.clone(),
            name: "vercel production source".to_string(),
            priority: 100,
            rules: vec![PolicyRule {
                actor: Actor::Integration("vercel".to_string()),
                token_id: None,
                environment_id: None,
                environment_kind: Some(EnvironmentKind::Production),
                path_glob: Some("packages/proprietary-engine/**".to_string()),
                key_glob: None,
                service_id: None,
                workspace_id: None,
                sensitivity: None,
                availability: None,
                actions: vec![PolicyAction::ReadBuildSource],
                decision: PolicyDecision::Allow,
                reason: Some("vercel can read production build source".to_string()),
            }],
        }]);
        let decision = engine.evaluate(&PolicyRequest {
            repository_id: repository_id.clone(),
            actor: Actor::Integration("vercel".to_string()),
            token_id: None,
            environment: Some(Environment {
                id: EnvironmentId::generated(),
                repository_id,
                name: "production".to_string(),
                kind: EnvironmentKind::Production,
            }),
            action: PolicyAction::ReadBuildSource,
            object: PolicyObject::Path("packages/proprietary-engine/index.ts".to_string()),
            path: Some("packages/proprietary-engine/index.ts".to_string()),
            key: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            deploy_source: None,
        });

        assert_eq!(decision.decision, PolicyDecision::Allow);
        assert_eq!(decision.audit.len(), 1);
    }

    #[test]
    fn repository_scope_prevents_cross_repo_policy_leaks() {
        let policy_repo_id = RepositoryId::generated();
        let request_repo_id = RepositoryId::generated();
        let engine = PolicyEngine::new(vec![VisibilityPolicy {
            id: PolicyId::generated(),
            repository_id: policy_repo_id,
            name: "public files".to_string(),
            priority: 1,
            rules: vec![PolicyRule {
                actor: Actor::Public,
                token_id: None,
                environment_id: None,
                environment_kind: None,
                path_glob: Some("**/*.ts".to_string()),
                key_glob: None,
                service_id: None,
                workspace_id: None,
                sensitivity: None,
                availability: None,
                actions: vec![PolicyAction::ReadBlob],
                decision: PolicyDecision::Allow,
                reason: None,
            }],
        }]);

        let decision = engine.evaluate(&PolicyRequest {
            repository_id: request_repo_id,
            actor: Actor::Public,
            token_id: None,
            environment: None,
            action: PolicyAction::ReadBlob,
            object: PolicyObject::Path("src/app.ts".to_string()),
            path: Some("src/app.ts".to_string()),
            key: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            deploy_source: None,
        });

        assert_eq!(decision.decision, PolicyDecision::Block);
        assert!(decision.matched_policy_id.is_none());
    }

    #[test]
    fn block_precedence_wins_over_higher_priority_allow() {
        let repository_id = RepositoryId::generated();
        let block_id = PolicyId::generated();
        let engine = PolicyEngine::new(vec![
            VisibilityPolicy {
                id: PolicyId::generated(),
                repository_id: repository_id.clone(),
                name: "allow vercel".to_string(),
                priority: 1000,
                rules: vec![PolicyRule {
                    actor: Actor::Integration("vercel".to_string()),
                    token_id: None,
                    environment_id: None,
                    environment_kind: Some(EnvironmentKind::Production),
                    path_glob: Some("**/*".to_string()),
                    key_glob: None,
                    service_id: None,
                    workspace_id: None,
                    sensitivity: None,
                    availability: None,
                    actions: vec![PolicyAction::ExportGit],
                    decision: PolicyDecision::Allow,
                    reason: Some("broad export allow".to_string()),
                }],
            },
            VisibilityPolicy {
                id: block_id.clone(),
                repository_id: repository_id.clone(),
                name: "block env".to_string(),
                priority: 1,
                rules: vec![PolicyRule {
                    actor: Actor::Integration("vercel".to_string()),
                    token_id: None,
                    environment_id: None,
                    environment_kind: Some(EnvironmentKind::Production),
                    path_glob: Some(".env.production".to_string()),
                    key_glob: None,
                    service_id: None,
                    workspace_id: None,
                    sensitivity: None,
                    availability: None,
                    actions: vec![PolicyAction::ExportGit],
                    decision: PolicyDecision::Block,
                    reason: Some("production env cannot be exported to git".to_string()),
                }],
            },
        ]);

        let decision = engine.evaluate(&PolicyRequest {
            repository_id: repository_id.clone(),
            actor: Actor::Integration("vercel".to_string()),
            token_id: None,
            environment: Some(Environment {
                id: EnvironmentId::generated(),
                repository_id,
                name: "production".to_string(),
                kind: EnvironmentKind::Production,
            }),
            action: PolicyAction::ExportGit,
            object: PolicyObject::Path(".env.production".to_string()),
            path: Some(".env.production".to_string()),
            key: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            deploy_source: None,
        });

        assert_eq!(decision.decision, PolicyDecision::Block);
        assert_eq!(decision.matched_policy_id, Some(block_id));
    }
}

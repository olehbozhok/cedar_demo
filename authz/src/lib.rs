use bon::builder;
use cedar_policy::{
	Authorizer, Context, Entities, EntitiesError, EntityUid, ParseErrors, PolicySet, Request,
	Response,
};

use std::str::FromStr;

#[derive(thiserror::Error, Debug)]
pub enum CheckError {
	#[error("could not parse principal: {0}")]
	Principal(ParseErrors),
	#[error("could not parse action: {0}")]
	Action(ParseErrors),
	#[error("could not parse resource: {0}")]
	Resource(ParseErrors),
	#[error("could not parse context from json: {0}")]
	ContextJsonParse(serde_json::Error),
	#[error("could not create context: {0}")]
	Context(cedar_policy::ContextJsonError),
	#[error("could not create request type: {0}")]
	Request(String),
	#[error("could not parse policy set: {0}")]
	PolicySet(ParseErrors),
	#[error("could not parse entities: {0}")]
	Entities(#[from] EntitiesError),
}

/// Is used to check policy based on raw params.  
/// Example of usage:
/// ```
/// let entities = include_str!("../../cedar_files/demo_entities.json");
///	let policy = include_str!("../../cedar_files/demo_policy.cedar");
///
/// let result = check()
/// 		.principal_str("User::\"Bob_user_id_uuid\"")
/// 		.action_str("Action::\"view\"")
/// 		.resource_str("Folder::\"public_folder_id_uuid\"")
/// 		.context_json_str("{}")
/// 		.policies_str(&policy)
/// 		.entities_json_str(&entities)
/// 		.call();
/// ```
#[builder]
pub fn check(
	principal_str: &str,
	action_str: &str,
	resource_str: &str,
	context_json_str: &str,
	policies_str: &str,
	entities_json_str: &str,
) -> Result<Response, CheckError> {
	let principal = EntityUid::from_str(principal_str).map_err(CheckError::Principal)?;
	let action = EntityUid::from_str(action_str).map_err(CheckError::Action)?;
	let resource = EntityUid::from_str(resource_str).map_err(CheckError::Resource)?;

	let context_json_val =
		serde_json::from_str(context_json_str).map_err(CheckError::ContextJsonParse)?;

	let context = Context::from_json_value(context_json_val, None).map_err(CheckError::Context)?;

	let request: Request =
		Request::new(Some(principal), Some(action), Some(resource), context, None)
			.map_err(|err| CheckError::Request(err.to_string()))?;

	let policy_set = PolicySet::from_str(policies_str).map_err(CheckError::PolicySet)?;

	let entities = Entities::from_json_str(entities_json_str, None)?;

	let authorizer = Authorizer::new();
	let decision = authorizer.is_authorized(&request, &policy_set, &entities);
	Ok(decision)
}

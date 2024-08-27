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
/// use authz::check;
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
/// match result {
///		Ok(v) => {
///			let decision = v.decision();
///			println!("decision: {decision:#?}")
///		}
///		Err(err) => println!("ERR: {err}"),
///	};
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

// test to check errors
#[cfg(test)]
mod tests {
	use super::*;
	use cedar_policy::Decision;

	// Reusable paths for entities and policy data.
	const ENTITIES: &str = include_str!("../../cedar_files/demo_entities.json");
	const POLICIES: &str = include_str!("../../cedar_files/demo_policy.cedar");

	#[test]
	fn test_valid_check() {
		let response = check()
			.principal_str("User::\"Bob_user_id_uuid\"")
			.action_str("Action::\"view\"")
			.resource_str("Folder::\"public_folder_id_uuid\"")
			.context_json_str("{}")
			.policies_str(POLICIES)
			.entities_json_str(ENTITIES)
			.call();

		assert!(
			response.is_ok(),
			"Expected Ok(Response), got Err: {:?}",
			response
		);
		if let Ok(response) = response {
			assert_eq!(response.decision(), Decision::Allow);
		}
	}

	#[test]
	fn test_check_forbidden_action() {
		let response = check()
			.principal_str("User::\"Anna_user_id_uuid\"")
			.action_str("Action::\"view\"")
			.resource_str("Folder::\"private_folder_id_uuid\"")
			.context_json_str("{}")
			.policies_str(POLICIES)
			.entities_json_str(ENTITIES)
			.call();

		assert!(
			response.is_ok(),
			"Expected Ok(Response), got Err: {:?}",
			response
		);
		if let Ok(response) = response {
			assert_eq!(response.decision(), Decision::Deny);
		}
	}

	// Error case: Principal parsing error
	#[test]
	fn test_principal_parse_error() {
		let response = check()
			.principal_str("InvalidPrincipal")
			.action_str("Action::\"view\"")
			.resource_str("Folder::\"public_folder_id_uuid\"")
			.context_json_str("{}")
			.policies_str(POLICIES)
			.entities_json_str(ENTITIES)
			.call();

		assert!(matches!(response, Err(CheckError::Principal(_))));
	}

	// Error case: Action parsing error
	#[test]
	fn test_action_parse_error() {
		let response = check()
			.principal_str("User::\"Bob_user_id_uuid\"")
			.action_str("InvalidAction")
			.resource_str("Folder::\"public_folder_id_uuid\"")
			.context_json_str("{}")
			.policies_str(POLICIES)
			.entities_json_str(ENTITIES)
			.call();

		assert!(matches!(response, Err(CheckError::Action(_))));
	}

	// Error case: Resource parsing error
	#[test]
	fn test_resource_parse_error() {
		let response = check()
			.principal_str("User::\"Bob_user_id_uuid\"")
			.action_str("Action::\"view\"")
			.resource_str("InvalidResource")
			.context_json_str("{}")
			.policies_str(POLICIES)
			.entities_json_str(ENTITIES)
			.call();

		assert!(matches!(response, Err(CheckError::Resource(_))));
	}

	// Error case: Context JSON parsing error
	#[test]
	fn test_context_json_parse_error() {
		let response = check()
			.principal_str("User::\"Bob_user_id_uuid\"")
			.action_str("Action::\"view\"")
			.resource_str("Folder::\"public_folder_id_uuid\"")
			.context_json_str("{invalid_json}")
			.policies_str(POLICIES)
			.entities_json_str(ENTITIES)
			.call();

		assert!(matches!(response, Err(CheckError::ContextJsonParse(_))));
	}

	// TODO: fix this test after adding schema validation
	// // Error case: Context creation error
	// #[test]
	// fn test_context_creation_error() {
	// 	// Assuming a specific context that might fail
	// 	let response = check()
	// 		.principal_str("User::\"Bob_user_id_uuid\"")
	// 		.action_str("Action::\"view\"")
	// 		.resource_str("Folder::\"public_folder_id_uuid\"")
	// 		.context_json_str("{\"key\": \"value\"}")
	// 		.policies_str(POLICIES)
	// 		.entities_json_str(ENTITIES)
	// 		.call();
	// 	match response {
	// 		Err(CheckError::Context(_)) => {}
	// 		v => assert!(
	// 			false,
	// 			"Expected Err(CheckError::Context(_)), but got {:?}",
	// 			v
	// 		),
	// 	}
	// }

	// TODO: fix this test after adding schema validation
	// // Error case: Request creation error
	// #[test]
	// fn test_request_creation_error() {
	// 	// Here we use an intentionally malformed action string that should cause the request creation to fail
	// 	let response = check()
	// 		.principal_str("User::\"Bob_user_id_uuid\"") // This should be valid
	// 		.action_str("Action::\"invalid_action!@#\"") // Intentionally malformed action to trigger error
	// 		.resource_str("Folder::\"public_folder_id_uuid\"") // This should be valid
	// 		.context_json_str("{}") // A simple valid context
	// 		.policies_str(POLICIES)
	// 		.entities_json_str(ENTITIES)
	// 		.call();

	// 	match response {
	// 		Err(CheckError::Request(_err)) => {
	// 			// Expected error occurred, test passes
	// 		}
	// 		v => {
	// 			// If any other result, the test fails
	// 			assert!(
	// 				false,
	// 				"Expected Err(CheckError::Request(_)), but got {:?}",
	// 				v
	// 			);
	// 		}
	// 	}
	// }

	// Error case: Policy set parsing error
	#[test]
	fn test_policy_set_parse_error() {
		let response = check()
			.principal_str("User::\"Bob_user_id_uuid\"")
			.action_str("Action::\"view\"")
			.resource_str("Folder::\"public_folder_id_uuid\"")
			.context_json_str("{}")
			.policies_str("invalid policy syntax")
			.entities_json_str(ENTITIES)
			.call();

		assert!(matches!(response, Err(CheckError::PolicySet(_))));
	}

	// Error case: Entities parsing error
	#[test]
	fn test_entities_parse_error() {
		let response = check()
			.principal_str("User::\"Bob_user_id_uuid\"")
			.action_str("Action::\"view\"")
			.resource_str("Folder::\"public_folder_id_uuid\"")
			.context_json_str("{}")
			.policies_str(POLICIES)
			.entities_json_str("invalid entities json")
			.call();

		assert!(matches!(response, Err(CheckError::Entities(_))));
	}
}

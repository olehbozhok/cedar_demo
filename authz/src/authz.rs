use cedar_policy::{
	Authorizer, Context, Entities, EntitiesError, EntityUid, ParseErrors, PolicySet, Request,
	Response,
};
use jwt::JWTDecoder;

mod jwt_data_handler;
use jwt_data_handler::{AuthzInputEntitiesError, AuthzInputRaw, DecodeTokensError};
pub(crate) mod jwt_tokens;

use std::str::FromStr;

pub struct Authz {
	app_name: Option<String>,
	jwt_dec: JWTDecoder,
	policy: PolicySet,
	//default entities for app
	entities: Entities,
}

#[derive(thiserror::Error, Debug)]
pub enum AuthzNewError {
	#[error("could not parse policy set: {0}")]
	PolicySet(ParseErrors),
	#[error("could not parse entities: {0}")]
	Entities(#[from] EntitiesError),
}

pub struct AuthzConfig {
	pub app_name: Option<String>,
	pub decoder: JWTDecoder,
	pub policies: String,
	pub default_entities_json: String,
}

impl Authz {
	pub fn new(config: AuthzConfig) -> Result<Authz, AuthzNewError> {
		let policy_set =
			PolicySet::from_str(config.policies.as_str()).map_err(AuthzNewError::PolicySet)?;
		let entities = Entities::from_json_str(config.default_entities_json.as_str(), None)?;

		Ok(Authz {
			app_name: config.app_name,
			jwt_dec: config.decoder,
			policy: policy_set,
			entities,
		})
	}
}

#[derive(thiserror::Error, Debug)]
pub enum HandleError {
	#[error("could not parse input data json from string: {0}")]
	InputJsonParse(serde_json::Error),
	#[error("could not decode jwt tokens: {0}")]
	DecodeTokens(#[from] DecodeTokensError),

	#[error("could not parse action: {0}")]
	Action(ParseErrors),
	#[error("could not parse resource from json: {0}")]
	Resource(String),
	#[error("could not get entities from input: {0}")]
	AuthzInputEntities(#[from] AuthzInputEntitiesError),
	#[error("could not add entities values to entities list: {0}")]
	AddEntities(#[from] EntitiesError),
	#[error("could not create context: {0}")]
	Context(cedar_policy::ContextJsonError),
	#[error("could not create request type: {0}")]
	Request(String),
}

impl Authz {
	pub fn handle_raw_input(&self, data: &str) -> Result<Response, HandleError> {
		let input: jwt_data_handler::AuthzInputRaw =
			serde_json::from_str(data).map_err(HandleError::InputJsonParse)?;

		self.handle(input)
	}

	pub fn handle(&self, input: AuthzInputRaw) -> Result<Response, HandleError> {
		let decoded_input = input.decode_tokens(&self.jwt_dec)?;
		let params = decoded_input.chedar_params;
		let action = EntityUid::from_str(params.action.as_str()).map_err(HandleError::Action)?;
		let resource = EntityUid::from_json(params.resource)
			.map_err(|err| HandleError::Resource(err.to_string()))?;

		// TODO: add entities from trust store about issuers (like in cedarling)

		let jwt_entities = decoded_input.jwt.entities(self.app_name.as_deref())?;

		let entities = self
			.entities
			.clone()
			.add_entities(jwt_entities.entities, None)?;

		let principal = jwt_entities.user_entity_uid;

		let context =
			Context::from_json_value(params.context, None).map_err(HandleError::Context)?;

		let request: Request =
			Request::new(Some(principal), Some(action), Some(resource), context, None)
				.map_err(|err| HandleError::Request(err.to_string()))?;

		let authorizer = Authorizer::new();
		let decision = authorizer.is_authorized(&request, &self.policy, &entities);
		Ok(decision)
	}
}

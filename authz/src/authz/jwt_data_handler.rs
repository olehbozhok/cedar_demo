use cedar_policy::Entity;
use cedar_policy::EntityUid;

use super::jwt_tokens::{AccessToken, EntityCreatingError, IdToken, UserInfoToken};

#[derive(serde::Deserialize, Debug)]
pub struct AuthzInputRaw {
	// generates entities
	pub id_token: String,
	pub userinfo_token: String,
	pub access_token: String,

	#[serde(flatten)]
	pub extra: CedarParams,
}

#[derive(serde::Deserialize, Debug)]
pub struct CedarParams {
	// extra parameters for cedar decision resolution
	pub action: String,
	pub resource: serde_json::Value,
	pub context: serde_json::Value,
}

#[derive(thiserror::Error, Debug)]
pub enum DecodeTokensError {
	#[error("could not decode id_token: {0}")]
	IdToken(jwt::DecodeError),
	#[error("could not decode userinfo_token: {0}")]
	UserInfoToken(jwt::DecodeError),
	#[error("could not decode access_token: {0}")]
	AccessToken(jwt::DecodeError),
}

impl AuthzInputRaw {
	pub fn decode_tokens(self, decoder: &jwt::JWTDecoder) -> Result<AuthzInput, DecodeTokensError> {
		let id_token: IdToken = decoder
			.decode(&self.id_token)
			.map_err(DecodeTokensError::IdToken)?;

		let userinfo_token: UserInfoToken = decoder
			.decode(&self.userinfo_token)
			.map_err(DecodeTokensError::UserInfoToken)?;

		let access_token: AccessToken = decoder
			.decode(&self.access_token)
			.map_err(DecodeTokensError::AccessToken)?;

		Ok(AuthzInput {
			jwt: JWTData {
				id_token,
				userinfo_token,
				access_token,
			},
			chedar_params: self.extra,
		})
	}
}

#[derive(Debug)]
pub struct JWTData {
	pub id_token: IdToken,
	pub userinfo_token: UserInfoToken,
	pub access_token: AccessToken,
}

#[derive(Debug)]
pub struct AuthzInput {
	// jwt tokens
	pub jwt: JWTData,

	pub chedar_params: CedarParams,
}

#[derive(thiserror::Error, Debug)]
pub enum AuthzInputEntitiesError {
	#[error("could not get id token entity from id_token: {0}")]
	IdTokenEntity(EntityCreatingError),

	#[error("could not get user entity from userinfo_token: {0}")]
	UserEntity(EntityCreatingError),

	#[error("could not get access token entity from access_token: {0}")]
	AccessTokenEntity(EntityCreatingError),
	#[error("could not get application entity from access_token: {0}")]
	ApplicationEntity(EntityCreatingError),
}

pub struct JWTDataEntities {
	pub entities: Vec<Entity>,
	pub user_entity_uid: EntityUid,
}

impl JWTData {
	pub fn entities(
		self,
		application_name: Option<&str>,
	) -> Result<JWTDataEntities, AuthzInputEntitiesError> {
		// TODO: implement check of token correctness
		// // check if `aud` claim in id_token matches `client_id` in access token
		// if id_token.aud != access_token.client_id && super::REQUIRE_AUD_VALIDATION.get().cloned().unwrap_or(false) {
		// 	throw_str("id_token was not issued for this client: (id_token.aud != access_token.client_id)")
		// }

		// // check if both tokens were issued by the same issuer
		// if id_token.iss != access_token.iss {
		// 	throw_str("access_token and id_token weren't issued by the same issuer: (access_token.iss != id_token.iss)")
		// }
		// if userinfo.sub != id_token.sub || userinfo.iss != id_token.iss {
		// 	throw_str("userinfo token invalid: either sub or iss doesn't match id_token")
		// }

		let id_token_entity = self
			.id_token
			.get_token_entity()
			.map_err(AuthzInputEntitiesError::IdTokenEntity)?;

		let user_entity = self
			.userinfo_token
			.get_user_entity(&[])
			.map_err(AuthzInputEntitiesError::UserEntity)?;

		let user_entity_uid = user_entity.uid();

		let client_entity = self
			.access_token
			.get_client_entity()
			.map_err(AuthzInputEntitiesError::AccessTokenEntity)?;

		let client_entity_uid = client_entity.uid();

		let mut list = vec![id_token_entity, user_entity, client_entity];

		if let Option::Some(name) = application_name {
			let application_entity = self
				.access_token
				.get_application_entity(name, client_entity_uid)
				.map_err(AuthzInputEntitiesError::ApplicationEntity)?;
			list.push(application_entity)
		}

		Ok(JWTDataEntities {
			entities: list,
			user_entity_uid,
		})
	}
}

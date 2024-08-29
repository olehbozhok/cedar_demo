use std::collections::{BTreeSet, HashMap, HashSet};

use cedar_policy::Entity;
use cedar_policy::EntityAttrEvaluationError;
use cedar_policy::EntityUid;
use cedar_policy::RestrictedExpression;

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
pub enum EntityCreatingError {
	#[error("could not create entity uid from json: {0}")]
	CreateFromJson(anyhow::Error),
	#[error("could not create new entity: {0}")]
	NewEntity(#[from] EntityAttrEvaluationError),
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

#[derive(serde::Deserialize, Debug)]
pub struct IdToken {
	pub jti: String,

	pub iss: String,
	pub aud: String,
	pub sub: String,

	pub iat: i64,
	pub exp: i64,

	pub acr: Option<String>,
	pub azp: Option<String>,
	#[serde(default)]
	pub amr: BTreeSet<String>,

	#[serde(flatten)]
	extra: HashMap<String, serde_json::Value>,
}

impl IdToken {
	pub fn get_token_entity(self) -> Result<Entity, EntityCreatingError> {
		let id = serde_json::json!({ "__entity": { "type": "IdToken", "id": self.jti } });
		let uid = EntityUid::from_json(id)
			.map_err(|err| EntityCreatingError::CreateFromJson(err.into()))?;

		// TODO: develop this code after adding "trust store" (code from cedarling)
		// let trust_store = unsafe {
		// 	crypto::TRUST_STORE
		// 		.get()
		// 		.expect_throw("TRUST_STORE not initialized")
		// };
		// let entry = trust_store
		// 	.get(&self.iss)
		// 	.expect_throw("Unable to extract TrustedIssuer from UserInfo iss");
		// let issuer = entry.issuer.get_entity();

		let amr = self
			.amr
			.iter()
			.map(|v| RestrictedExpression::new_string(v.to_owned()));

		let mut attrs = HashMap::from([
			(
				"jti".into(),
				RestrictedExpression::new_string(self.jti.clone()),
			),
			// (
			// 	"iss".into(),
			// 	RestrictedExpression::new_entity_uid(issuer.uid()),
			// ),
			("aud".into(), RestrictedExpression::new_string(self.aud)),
			("sub".into(), RestrictedExpression::new_string(self.sub)),
			("iat".into(), RestrictedExpression::new_long(self.iat)),
			("exp".into(), RestrictedExpression::new_long(self.exp)),
			("amr".into(), RestrictedExpression::new_set(amr)),
		]);

		// optional member
		if let Some(azp) = self.azp {
			let _ = attrs.insert("azp".into(), RestrictedExpression::new_string(azp));
		}

		if let Some(acr) = self.acr {
			let _ = attrs.insert("acr".into(), RestrictedExpression::new_string(acr));
		}

		Ok(Entity::new(uid, attrs, HashSet::with_capacity(0))?)
	}
}

#[derive(serde::Deserialize, Debug)]
pub struct UserInfoToken {
	pub jti: String,
	pub iss: String,

	pub sub: String,
	pub aud: String,

	// it is not exist in demo token
	// pub exp: i64,
	// pub iat: i64,
	pub inum: String, // represent  user-id

	#[serde(flatten)]
	extra: HashMap<String, serde_json::Value>,
}

// Restricted expressions can contain only the following:
//   - bool, int, and string literals
//   - literal `EntityUid`s such as `User::"alice"`
//   - extension function calls, where the arguments must be other things
//       on this list
//   - set and record literals, where the values must be other things on
//       this list
fn json_to_expression(value: serde_json::Value) -> Option<RestrictedExpression> {
	match value {
		serde_json::Value::Null => None,
		serde_json::Value::Bool(v) => Some(RestrictedExpression::new_bool(v)),
		serde_json::Value::Number(v) => {
			if let Option::Some(i) = v.as_i64() {
				Some(RestrictedExpression::new_long(i))
			} else if let Option::Some(f) = v.as_f64() {
				Some(RestrictedExpression::new_decimal(f.to_string()))
			} else {
				None
			}
		}
		serde_json::Value::String(v) => Some(RestrictedExpression::new_string(v)),
		serde_json::Value::Array(v) => Some(RestrictedExpression::new_set(
			v.into_iter()
				.filter_map(|v| json_to_expression(v))
				.collect::<Vec<RestrictedExpression>>(),
		)),
		serde_json::Value::Object(_) => None,
	}
}

impl UserInfoToken {
	pub fn get_user_entity(self, roles: &[Entity]) -> Result<Entity, EntityCreatingError> {
		// TODO: implemplement acfter adding trust sstore (code from cedarling)
		// let trust_store = unsafe { crypto::TRUST_STORE.get().expect_throw("TRUST_STORE not initialized") };
		// let entry = trust_store.get(&self.iss).expect_throw("Unable to extract TrustedIssuer from UserInfo iss");

		// let identifier = entry
		// 	.issuer
		// 	.id_tokens
		// 	.principal_identifier
		// 	.as_deref()
		// 	.unwrap_or("User");

		let identifier = "User";
		// self.sub
		let id = serde_json::json!({ "__entity": { "type": identifier, "id": self.inum } });
		let uid = EntityUid::from_json(id)
			.map_err(|err| EntityCreatingError::CreateFromJson(err.into()))?;

		// for demo we don`t use email field`
		// // create email dict
		// let mut iter = self.email.split('@');
		// let record = [
		// 	(
		// 		"id".to_string(),
		// 		RestrictedExpression::new_string(
		// 			iter.next().expect_throw("Invalid Email Address").into(),
		// 		),
		// 	),
		// 	(
		// 		"domain".to_string(),
		// 		RestrictedExpression::new_string(
		// 			iter.next().expect_throw("Invalid Email Address").into(),
		// 		),
		// 	),
		// ];

		// construct entity
		let mut attrs = HashMap::from([
			(
				"sub".to_string(),
				RestrictedExpression::new_string(self.sub.clone()),
			),
			// (
			// 	"email".to_string(),
			// 	RestrictedExpression::new_record(record).unwrap_throw(),
			// ),
		]);

		self.extra.into_iter().for_each(|(k, v)| {
			if let Option::Some(exp) = json_to_expression(v) {
				attrs.insert(k.to_owned(), exp);
			}
		});

		let parents = HashSet::from_iter(roles.iter().map(|e| e.uid()));
		Ok(Entity::new(uid, attrs, parents)?)
	}
}

#[derive(serde::Deserialize, Debug)]
pub struct AccessToken {
	pub jti: String,
	pub iss: String,

	aud: String,
	scope: HashSet<String>,
	pub client_id: String,

	exp: i64,
	iat: i64,

	#[serde(flatten)]
	extra: HashMap<String, serde_json::Value>,
}

impl AccessToken {
	pub fn get_client_entity(&self) -> Result<Entity, EntityCreatingError> {
		let id = serde_json::json!({ "__entity": { "type": "Client", "id": self.aud } });
		let id = EntityUid::from_json(id)
			.map_err(|err| EntityCreatingError::CreateFromJson(err.into()))?;

		let parents = HashSet::new();
		let attrs = HashMap::from([
			(
				"client_id".to_string(),
				RestrictedExpression::new_string(self.client_id.clone()),
			),
			(
				"iss".to_string(),
				RestrictedExpression::new_string(self.iss.clone()),
			),
		]);

		Ok(Entity::new(id, attrs, parents)?)
	}

	pub fn get_application_entity(
		&self,
		application_name: &str,
		client_uid: EntityUid,
	) -> Result<Entity, EntityCreatingError> {
		let id = serde_json::json!({ "__entity": { "type": "Application", "id": self.aud } });
		let id = EntityUid::from_json(id)
			.map_err(|err| EntityCreatingError::CreateFromJson(err.into()))?;

		let parents = HashSet::new();
		let attrs = HashMap::from([
			(
				"name".to_owned(),
				RestrictedExpression::new_string(application_name.to_string()),
			),
			(
				"client".to_owned(),
				RestrictedExpression::new_entity_uid(client_uid),
			),
		]);

		Ok(Entity::new(id, attrs, parents)?)
	}
}

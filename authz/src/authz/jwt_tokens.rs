use std::collections::{HashMap, HashSet};

use cedar_policy::Entity;
use cedar_policy::EntityAttrEvaluationError;
use cedar_policy::EntityUid;
use cedar_policy::RestrictedExpression;

use super::exp_parsers;

#[derive(thiserror::Error, Debug)]
pub enum EntityCreatingError {
	#[error("could not create entity uid from json: {0}")]
	CreateFromJson(String),
	#[error("create expression with email: {0}")]
	Email(#[from] exp_parsers::ParseEmailToExpError),
	#[error("could not create new entity: {0}")]
	NewEntity(#[from] EntityAttrEvaluationError),

	#[error("could not create new entity of trusted issuer: {0}")]
	TrustedIssuer(#[from] exp_parsers::TrustedIssuerEntityError),
}

#[derive(Default, Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdToken {
	pub acr: String,
	pub amr: Vec<String>,
	pub aud: String,
	pub birthdate: String,
	pub email: String,
	pub exp: i64,
	pub iat: i64,
	pub iss: String,
	pub jti: String,
	pub name: String,
	#[serde(rename = "phone_number")]
	pub phone_number: String,
	pub sub: String,
	// next fields is unused for now
	// #[serde(rename = "at_hash")]
	// pub at_hash: String,
	// pub country: String,

	// #[serde(rename = "user_name")]
	// pub user_name: String,

	// pub inum: String,
	// pub sid: String,
	// #[serde(rename = "jansOpenIDConnectVersion")]
	// pub jans_open_idconnect_version: String,

	// #[serde(rename = "updated_at")]
	// pub updated_at: i64,
	// #[serde(rename = "auth_time")]
	// pub auth_time: i64,
	// pub nickname: String,

	// #[serde(rename = "given_name")]
	// pub given_name: String,
	// #[serde(rename = "middle_name")]
	// pub middle_name: String,
	// pub nonce: String,

	// #[serde(rename = "c_hash")]
	// pub c_hash: String,
	// #[serde(rename = "user_permission")]
	// pub user_permission: Vec<String>,

	// pub grant: String,
	// #[serde(rename = "family_name")]
	// pub family_name: String,
	// pub status: Status,
	// #[serde(rename = "jansAdminUIRole")]
	// pub jans_admin_uirole: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
	#[serde(rename = "status_list")]
	pub status_list: StatusList,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusList {
	pub idx: i64,
	pub uri: String,
}

impl IdToken {
	pub fn get_token_entities(self) -> Result<Vec<Entity>, EntityCreatingError> {
		let id = serde_json::json!({ "__entity": { "type": "Jans::id_token", "id": self.jti } });
		let uid = EntityUid::from_json(id)
			.map_err(|err| EntityCreatingError::CreateFromJson(err.to_string()))?;

		let amr = self
			.amr
			.iter()
			.map(|v| RestrictedExpression::new_string(v.to_owned()));

		// TODO: add
		//         iss: TrustedIssuer,

		let mut attrs = HashMap::from([
			("acr".into(), RestrictedExpression::new_string(self.acr)),
			("amr".into(), RestrictedExpression::new_set(amr)),
			("aud".into(), RestrictedExpression::new_string(self.aud)),
			(
				"birthdate".into(),
				RestrictedExpression::new_string(self.birthdate),
			),
			("email".into(), exp_parsers::email_exp(&self.email)?),
			("exp".into(), RestrictedExpression::new_long(self.exp)),
			("iat".into(), RestrictedExpression::new_long(self.iat)),
			("jti".into(), RestrictedExpression::new_string(self.jti)),
			("name".into(), RestrictedExpression::new_string(self.name)),
			(
				"phone_number".into(),
				RestrictedExpression::new_string(self.phone_number),
			),
			("sub".into(), RestrictedExpression::new_string(self.sub)),
		]);

		let trusted_issuer_entity = exp_parsers::trusted_issuer_entity(&self.iss)?;

		attrs.insert(
			"iss".into(),
			RestrictedExpression::new_entity_uid(trusted_issuer_entity.uid()),
		);

		let id_token_entity = Entity::new(uid, attrs, HashSet::with_capacity(0))?;
		let result = vec![id_token_entity, trusted_issuer_entity];
		Ok(result)
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
			.map_err(|err| EntityCreatingError::CreateFromJson(err.to_string()))?;

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
#[allow(dead_code)]
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
			.map_err(|err| EntityCreatingError::CreateFromJson(err.to_string()))?;

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
			.map_err(|err| EntityCreatingError::CreateFromJson(err.to_string()))?;

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

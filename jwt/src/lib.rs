// TODO: implement
pub struct JWTValidationConfig {}

pub enum JWTDecoder {
	WithValidation(JWTValidationConfig),
	WithoutValidation,
}

impl JWTDecoder {
	pub fn new_without_validation() -> Self {
		Self::WithoutValidation
	}
}

impl JWTDecoder {
	pub fn decode<T: serde::de::DeserializeOwned>(&self, jwt: &str) -> Result<T, DecodeError> {
		match self {
			JWTDecoder::WithValidation(_config) => todo!(),
			JWTDecoder::WithoutValidation => decode_jwt_without_validation(jwt),
		}
	}
}

#[derive(thiserror::Error, Debug)]
pub enum DecodeError {
	#[error("Malformed JWT provided")]
	MalformedJWT,
	#[error("Unable to parse JWT as valid base64 encoded JSON")]
	UnableToParseBase64AsJson(serde_json::Error),
}

pub fn decode_jwt_without_validation<T: serde::de::DeserializeOwned>(
	jwt: &str,
) -> Result<T, DecodeError> {
	let payload = jwt.split('.').nth(1).ok_or(DecodeError::MalformedJWT)?;
	Ok(serde_json::from_str(payload).map_err(DecodeError::UnableToParseBase64AsJson)?)
}

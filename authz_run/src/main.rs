use authz::{check, jwt, Authz, AuthzConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	if let Result::Err(err) = real_demo_case() {
		println!("got error in demo case: {}", err);
	};
	Ok(())
}

fn real_demo_case() -> Result<(), Box<dyn std::error::Error>> {
	println!("start real_demo_case");

	let input_json = include_str!("../../cedar_files/input.json");

	let authz = Authz::new(AuthzConfig {
		app_name: Some("Demo_App".to_owned()),
		decoder: jwt::JWTDecoder::new_without_validation(),
		policy: authz::PolicyStoreConfig::Local,
	})?;

	let v = authz.handle_raw_input(&input_json)?;
	let decision = v.decision();
	println!("decision: {decision:#?}");
	Ok(())
}

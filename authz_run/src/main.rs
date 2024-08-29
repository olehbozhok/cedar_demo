use authz::{jwt, Authz, AuthzConfig};
use simplelog::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let _ = SimpleLogger::init(LevelFilter::Info, Config::default());

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

	// only show entities for debug
	{
		let q = authz::AuthzInputRaw::parse_raw(input_json)?;
		let decoded_input = q.decode_tokens(&jwt::JWTDecoder::new_without_validation())?;
		let entites_box = authz.get_entities(decoded_input.jwt)?;

		if let Err(e) = entites_box.entities.write_to_json(std::io::stdout()) {
			eprintln!("Error writing to JSON: {:?}", e);
		}
	}

	let v = authz.handle_raw_input(&input_json)?;
	let decision = v.decision();
	println!("decision: {decision:#?}");
	Ok(())
}

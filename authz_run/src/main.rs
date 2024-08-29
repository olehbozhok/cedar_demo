use authz::{check, jwt, Authz, AuthzConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	basic_case();

	if let Result::Err(err) = real_demo_case() {
		println!("got error in demo case: {}", err);
	};
	Ok(())
}

fn basic_case() {
	let entities = include_str!("../../cedar_files/demo_entities.json");
	let policy = include_str!("../../cedar_files/demo_policy.cedar");

	let result = check()
		.principal_str("User::\"Bob_user_id_uuid\"")
		.action_str("Action::\"view\"")
		.resource_str("Folder::\"public_folder_id_uuid\"")
		.context_json_str("{}")
		.policies_str(&policy)
		.entities_json_str(&entities)
		.call();

	println!("result of basic case:");
	match result {
		Ok(v) => {
			let decision = v.decision();
			println!("decision: {decision:#?}")
		}
		Err(err) => println!("ERR: {err}"),
	};
}

fn real_demo_case() -> Result<(), Box<dyn std::error::Error>> {
	println!("start real_demo_case");

	let entities = include_str!("../../cedar_files/demo_entities.json");
	let policy = include_str!("../../cedar_files/demo_policy.cedar");
	let input_json = include_str!("../../cedar_files/input.json");

	let authz = Authz::new(AuthzConfig {
		app_name: Some("Demo_App".to_owned()),
		decoder: jwt::JWTDecoder::new_without_validation(),
		default_entities_json: entities.to_owned(),
		policies: policy.to_owned(),
	})?;

	let v = authz.handle_raw_input(&input_json)?;
	let decision = v.decision();
	println!("decision: {decision:#?}");
	Ok(())
}

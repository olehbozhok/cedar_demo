use authz::check;

fn main() {
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

	match result {
		Ok(v) => {
			let decision = v.decision();
			println!("decision: {decision:#?}")
		}
		Err(err) => println!("ERR: {err}"),
	};
}

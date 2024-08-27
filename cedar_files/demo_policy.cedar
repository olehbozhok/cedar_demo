// allow all users to read public resource
permit (
    principal,
    action == Action::"view",
    resource
)
when { resource.accessLevel == "public" };

// forbid to do somthening if the resource has attribute allowed_location and user from another one and it is not owner
forbid (principal, action, resource)
when
{
    resource.user_owner_id != principal &&
    resource has allowed_location &&
    !principal.location in resource.allowed_location
};

// allow view, edit, ... if the owner is principal (current user)
permit (
    principal,
    action in
        [Action::"view",
         Action::"add_file",
         Action::"egit_file",
         Action::"delete_file"],
    resource
)
when { resource.user_owner_id == principal };

//allow to view private folder only if the principal in the shared list
permit (
    principal,
    action == Action::"view",
    resource
)
when
{
    resource.accessLevel == "private" &&
    principal in resource.shared_user_id_list
};
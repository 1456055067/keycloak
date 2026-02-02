//! Admin API router configuration.
//!
//! Provides functions to create Axum routers for the Admin API endpoints.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use kc_storage::{ClientProvider, CredentialProvider, RealmProvider, RoleProvider, UserProvider};

use crate::dto::{
    ClientRepresentation, ClientSearchParams, ClientSecretResponse, CreateClientRequest,
    CreateRealmRequest, CreateRoleRequest, CreateUserRequest, RealmRepresentation, RealmSummary,
    RoleRepresentation, RoleSearchParams, UpdateClientRequest, UpdateRealmRequest,
    UpdateRoleRequest, UpdateUserRequest, UserRepresentation, UserSearchParams,
};
use crate::error::{AdminError, AdminResult};
use crate::state::{ClientState, RoleState, UserState};

// ============================================================================
// Realm Handlers
// ============================================================================

/// GET /admin/realms - List all realms
async fn list_realms<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
) -> AdminResult<Json<Vec<RealmSummary>>>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    let realms = state.realm_provider.list().await?;
    let summaries: Vec<RealmSummary> = realms.into_iter().map(RealmSummary::from).collect();
    Ok(Json(summaries))
}

/// POST /admin/realms - Create a new realm
async fn create_realm<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Json(request): Json<CreateRealmRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    // Validate realm name
    if request.realm.is_empty() {
        return Err(AdminError::Validation(
            "Realm name cannot be empty".to_string(),
        ));
    }

    // Check for reserved realm names
    if request.realm == "master" && state.realm_provider.exists_by_name("master").await? {
        return Err(AdminError::conflict("Realm", "name", "master"));
    }

    // Convert request to domain model
    let realm = request.into_realm();
    let realm_name = realm.name.clone();

    // Create the realm
    state.realm_provider.create(&realm).await.map_err(|e| {
        if e.is_duplicate() {
            AdminError::conflict("Realm", "name", &realm_name)
        } else {
            AdminError::from(e)
        }
    })?;

    // Return 201 Created with Location header
    Ok((
        StatusCode::CREATED,
        [("Location", format!("/admin/realms/{}", realm_name))],
    ))
}

/// GET /admin/realms/{realm} - Get realm by name
async fn get_realm<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Path(realm_name): Path<String>,
) -> AdminResult<Json<RealmRepresentation>>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    Ok(Json(RealmRepresentation::from(realm)))
}

/// PUT /admin/realms/{realm} - Update a realm
async fn update_realm<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Path(realm_name): Path<String>,
    Json(request): Json<UpdateRealmRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    // Get existing realm
    let mut realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Apply updates
    request.apply_to(&mut realm);

    // Save updates
    state.realm_provider.update(&realm).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/realms/{realm} - Delete a realm
async fn delete_realm<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Path(realm_name): Path<String>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    // Protect master realm from deletion
    if realm_name == "master" {
        return Err(AdminError::Forbidden(
            "Cannot delete the master realm".to_string(),
        ));
    }

    // Get the realm to get its ID
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Delete the realm
    state.realm_provider.delete(realm.id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// User Handlers
// ============================================================================

/// GET /admin/realms/{realm}/users - List/search users
async fn get_users<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Path(realm_name): Path<String>,
    Query(params): Query<UserSearchParams>,
) -> AdminResult<Json<Vec<UserRepresentation>>>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Search users
    let criteria = params.into_criteria();
    let users = state.user_provider.search(realm.id, &criteria).await?;

    // Convert to representations
    let representations: Vec<UserRepresentation> =
        users.into_iter().map(UserRepresentation::from).collect();

    Ok(Json(representations))
}

/// POST /admin/realms/{realm}/users - Create a user
async fn create_user<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Path(realm_name): Path<String>,
    Json(request): Json<CreateUserRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Validate username
    if request.username.is_empty() {
        return Err(AdminError::Validation(
            "Username cannot be empty".to_string(),
        ));
    }

    // Check for duplicate username
    if state
        .user_provider
        .get_by_username(realm.id, &request.username)
        .await?
        .is_some()
    {
        return Err(AdminError::conflict("User", "username", &request.username));
    }

    // Check for duplicate email if provided and realm doesn't allow duplicates
    if let Some(ref email) = request.email {
        if !realm.duplicate_emails_allowed
            && state
                .user_provider
                .get_by_email(realm.id, email)
                .await?
                .is_some()
        {
            return Err(AdminError::conflict("User", "email", email));
        }
    }

    // Convert to domain model
    let user = request.into_user(realm.id);
    let user_id = user.id;
    let username = user.username.clone();

    // Create the user
    state.user_provider.create(&user).await.map_err(|e| {
        if e.is_duplicate() {
            AdminError::conflict("User", "username", &username)
        } else {
            AdminError::from(e)
        }
    })?;

    // Return 201 Created with Location header
    Ok((
        StatusCode::CREATED,
        [(
            "Location",
            format!("/admin/realms/{}/users/{}", realm_name, user_id),
        )],
    ))
}

/// GET /admin/realms/{realm}/users/{id} - Get user by ID
async fn get_user<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Path((realm_name, user_id)): Path<(String, uuid::Uuid)>,
) -> AdminResult<Json<UserRepresentation>>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get user
    let user = state
        .user_provider
        .get_by_id(realm.id, user_id)
        .await?
        .ok_or_else(|| AdminError::not_found_id("User", user_id))?;

    Ok(Json(UserRepresentation::from(user)))
}

/// PUT /admin/realms/{realm}/users/{id} - Update a user
async fn update_user<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Path((realm_name, user_id)): Path<(String, uuid::Uuid)>,
    Json(request): Json<UpdateUserRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get existing user
    let mut user = state
        .user_provider
        .get_by_id(realm.id, user_id)
        .await?
        .ok_or_else(|| AdminError::not_found_id("User", user_id))?;

    // Check for username conflict if changing username
    if let Some(ref new_username) = request.username {
        if new_username != &user.username {
            if let Some(existing) = state
                .user_provider
                .get_by_username(realm.id, new_username)
                .await?
            {
                if existing.id != user_id {
                    return Err(AdminError::conflict("User", "username", new_username));
                }
            }
        }
    }

    // Check for email conflict if changing email
    if let Some(ref new_email) = request.email {
        if user.email.as_ref() != Some(new_email) && !realm.duplicate_emails_allowed {
            if let Some(existing) = state.user_provider.get_by_email(realm.id, new_email).await? {
                if existing.id != user_id {
                    return Err(AdminError::conflict("User", "email", new_email));
                }
            }
        }
    }

    // Apply updates
    request.apply_to(&mut user);

    // Save updates
    state.user_provider.update(&user).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/realms/{realm}/users/{id} - Delete a user
async fn delete_user<R, U, Cr>(
    State(state): State<UserState<R, U, Cr>>,
    Path((realm_name, user_id)): Path<(String, uuid::Uuid)>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Verify user exists
    if state
        .user_provider
        .get_by_id(realm.id, user_id)
        .await?
        .is_none()
    {
        return Err(AdminError::not_found_id("User", user_id));
    }

    // Delete the user
    state.user_provider.delete(realm.id, user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Client Handlers
// ============================================================================

/// GET /admin/realms/{realm}/clients - List/search clients
async fn get_clients<R, C>(
    State(state): State<ClientState<R, C>>,
    Path(realm_name): Path<String>,
    Query(params): Query<ClientSearchParams>,
) -> AdminResult<Json<Vec<ClientRepresentation>>>
where
    R: RealmProvider,
    C: ClientProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Search clients
    let criteria = params.into_criteria();
    let clients = state.client_provider.search(realm.id, &criteria).await?;

    // Convert to representations
    let representations: Vec<ClientRepresentation> = clients
        .into_iter()
        .map(ClientRepresentation::from)
        .collect();

    Ok(Json(representations))
}

/// POST /admin/realms/{realm}/clients - Create a client
async fn create_client<R, C>(
    State(state): State<ClientState<R, C>>,
    Path(realm_name): Path<String>,
    Json(request): Json<CreateClientRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Validate client_id
    if request.client_id.is_empty() {
        return Err(AdminError::Validation(
            "Client ID cannot be empty".to_string(),
        ));
    }

    // Check for duplicate client_id
    if state
        .client_provider
        .get_by_client_id(realm.id, &request.client_id)
        .await?
        .is_some()
    {
        return Err(AdminError::conflict("Client", "clientId", &request.client_id));
    }

    // Convert to domain model
    let client = request.into_client(realm.id);
    let client_id = client.id;
    let client_id_str = client.client_id.clone();

    // Create the client
    state.client_provider.create(&client).await.map_err(|e| {
        if e.is_duplicate() {
            AdminError::conflict("Client", "clientId", &client_id_str)
        } else {
            AdminError::from(e)
        }
    })?;

    // Return 201 Created with Location header
    Ok((
        StatusCode::CREATED,
        [(
            "Location",
            format!("/admin/realms/{}/clients/{}", realm_name, client_id),
        )],
    ))
}

/// GET /admin/realms/{realm}/clients/{id} - Get client by ID
async fn get_client<R, C>(
    State(state): State<ClientState<R, C>>,
    Path((realm_name, client_id)): Path<(String, uuid::Uuid)>,
) -> AdminResult<Json<ClientRepresentation>>
where
    R: RealmProvider,
    C: ClientProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get client
    let client = state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .ok_or_else(|| AdminError::not_found_id("Client", client_id))?;

    Ok(Json(ClientRepresentation::from(client)))
}

/// PUT /admin/realms/{realm}/clients/{id} - Update a client
async fn update_client<R, C>(
    State(state): State<ClientState<R, C>>,
    Path((realm_name, client_id)): Path<(String, uuid::Uuid)>,
    Json(request): Json<UpdateClientRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get existing client
    let mut client = state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .ok_or_else(|| AdminError::not_found_id("Client", client_id))?;

    // Apply updates (client_id cannot be changed)
    request.apply_to(&mut client);

    // Save updates
    state.client_provider.update(&client).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/realms/{realm}/clients/{id} - Delete a client
async fn delete_client<R, C>(
    State(state): State<ClientState<R, C>>,
    Path((realm_name, client_id)): Path<(String, uuid::Uuid)>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Verify client exists
    if state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .is_none()
    {
        return Err(AdminError::not_found_id("Client", client_id));
    }

    // Delete the client
    state.client_provider.delete(realm.id, client_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /admin/realms/{realm}/clients/{id}/client-secret - Get client secret
async fn get_client_secret<R, C>(
    State(state): State<ClientState<R, C>>,
    Path((realm_name, client_id)): Path<(String, uuid::Uuid)>,
) -> AdminResult<Json<ClientSecretResponse>>
where
    R: RealmProvider,
    C: ClientProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get client
    let client = state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .ok_or_else(|| AdminError::not_found_id("Client", client_id))?;

    // Public clients don't have secrets
    if client.public_client {
        return Err(AdminError::BadRequest(
            "Public clients do not have a client secret".to_string(),
        ));
    }

    Ok(Json(ClientSecretResponse {
        value: client.secret,
    }))
}

/// POST /admin/realms/{realm}/clients/{id}/client-secret - Regenerate client secret
async fn regenerate_client_secret<R, C>(
    State(state): State<ClientState<R, C>>,
    Path((realm_name, client_id)): Path<(String, uuid::Uuid)>,
) -> AdminResult<Json<ClientSecretResponse>>
where
    R: RealmProvider,
    C: ClientProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get client to check if it's public
    let client = state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .ok_or_else(|| AdminError::not_found_id("Client", client_id))?;

    // Public clients don't have secrets
    if client.public_client {
        return Err(AdminError::BadRequest(
            "Public clients do not have a client secret".to_string(),
        ));
    }

    // Regenerate secret using the provider
    let new_secret = state.client_provider.regenerate_secret(realm.id, client_id).await?;

    Ok(Json(ClientSecretResponse {
        value: Some(new_secret),
    }))
}

// ============================================================================
// Role Handlers
// ============================================================================

/// GET /admin/realms/{realm}/roles - List realm roles
async fn get_realm_roles<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path(realm_name): Path<String>,
    Query(params): Query<RoleSearchParams>,
) -> AdminResult<Json<Vec<RoleRepresentation>>>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Search realm roles
    let criteria = params.into_realm_criteria();
    let roles = state.role_provider.search(realm.id, &criteria).await?;

    // Convert to representations
    let representations: Vec<RoleRepresentation> =
        roles.into_iter().map(RoleRepresentation::from).collect();

    Ok(Json(representations))
}

/// POST /admin/realms/{realm}/roles - Create a realm role
async fn create_realm_role<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path(realm_name): Path<String>,
    Json(request): Json<CreateRoleRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Validate role name
    if request.name.is_empty() {
        return Err(AdminError::Validation(
            "Role name cannot be empty".to_string(),
        ));
    }

    // Check for duplicate role name
    if state
        .role_provider
        .get_realm_role_by_name(realm.id, &request.name)
        .await?
        .is_some()
    {
        return Err(AdminError::conflict("Role", "name", &request.name));
    }

    // Convert to domain model
    let role = request.into_realm_role(realm.id);
    let role_name = role.name.clone();

    // Create the role
    state.role_provider.create(&role).await.map_err(|e| {
        if e.is_duplicate() {
            AdminError::conflict("Role", "name", &role_name)
        } else {
            AdminError::from(e)
        }
    })?;

    // Return 201 Created with Location header
    Ok((
        StatusCode::CREATED,
        [(
            "Location",
            format!("/admin/realms/{}/roles/{}", realm_name, role_name),
        )],
    ))
}

/// GET /admin/realms/{realm}/roles/{role-name} - Get realm role by name
async fn get_realm_role<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, role_name)): Path<(String, String)>,
) -> AdminResult<Json<RoleRepresentation>>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get role
    let role = state
        .role_provider
        .get_realm_role_by_name(realm.id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    Ok(Json(RoleRepresentation::from(role)))
}

/// PUT /admin/realms/{realm}/roles/{role-name} - Update a realm role
async fn update_realm_role<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, role_name)): Path<(String, String)>,
    Json(request): Json<UpdateRoleRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get existing role
    let mut role = state
        .role_provider
        .get_realm_role_by_name(realm.id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    // Check for name conflict if changing name
    if let Some(ref new_name) = request.name {
        if new_name != &role.name {
            if state
                .role_provider
                .get_realm_role_by_name(realm.id, new_name)
                .await?
                .is_some()
            {
                return Err(AdminError::conflict("Role", "name", new_name));
            }
        }
    }

    // Apply updates
    request.apply_to(&mut role);

    // Save updates
    state.role_provider.update(&role).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/realms/{realm}/roles/{role-name} - Delete a realm role
async fn delete_realm_role<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, role_name)): Path<(String, String)>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get role to get its ID
    let role = state
        .role_provider
        .get_realm_role_by_name(realm.id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    // Delete the role
    state.role_provider.delete(realm.id, role.id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /admin/realms/{realm}/roles/{role-name}/composites - Get composite roles
async fn get_realm_role_composites<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, role_name)): Path<(String, String)>,
) -> AdminResult<Json<Vec<RoleRepresentation>>>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get role
    let role = state
        .role_provider
        .get_realm_role_by_name(realm.id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    // Get composites
    let composites = state.role_provider.get_composites(realm.id, role.id).await?;

    let representations: Vec<RoleRepresentation> = composites
        .into_iter()
        .map(RoleRepresentation::from)
        .collect();

    Ok(Json(representations))
}

/// POST /admin/realms/{realm}/roles/{role-name}/composites - Add composite roles
async fn add_realm_role_composites<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, role_name)): Path<(String, String)>,
    Json(request): Json<Vec<RoleRepresentation>>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get composite role
    let role = state
        .role_provider
        .get_realm_role_by_name(realm.id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    // Add each role as a composite
    for role_repr in request {
        state
            .role_provider
            .add_composite(realm.id, role.id, role_repr.id)
            .await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/realms/{realm}/roles/{role-name}/composites - Remove composite roles
async fn remove_realm_role_composites<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, role_name)): Path<(String, String)>,
    Json(request): Json<Vec<RoleRepresentation>>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Get composite role
    let role = state
        .role_provider
        .get_realm_role_by_name(realm.id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    // Remove each role from composites
    for role_repr in request {
        state
            .role_provider
            .remove_composite(realm.id, role.id, role_repr.id)
            .await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Client Role Handlers
// ============================================================================

/// GET /admin/realms/{realm}/clients/{id}/roles - List client roles
async fn get_client_roles<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, client_id)): Path<(String, uuid::Uuid)>,
    Query(params): Query<RoleSearchParams>,
) -> AdminResult<Json<Vec<RoleRepresentation>>>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Validate client exists
    if state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .is_none()
    {
        return Err(AdminError::not_found_id("Client", client_id));
    }

    // Search client roles
    let criteria = params.into_client_criteria(client_id);
    let roles = state.role_provider.search(realm.id, &criteria).await?;

    // Convert to representations
    let representations: Vec<RoleRepresentation> =
        roles.into_iter().map(RoleRepresentation::from).collect();

    Ok(Json(representations))
}

/// POST /admin/realms/{realm}/clients/{id}/roles - Create a client role
async fn create_client_role<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, client_id)): Path<(String, uuid::Uuid)>,
    Json(request): Json<CreateRoleRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Validate client exists
    if state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .is_none()
    {
        return Err(AdminError::not_found_id("Client", client_id));
    }

    // Validate role name
    if request.name.is_empty() {
        return Err(AdminError::Validation(
            "Role name cannot be empty".to_string(),
        ));
    }

    // Check for duplicate role name
    if state
        .role_provider
        .get_client_role_by_name(realm.id, client_id, &request.name)
        .await?
        .is_some()
    {
        return Err(AdminError::conflict("Role", "name", &request.name));
    }

    // Convert to domain model
    let role = request.into_client_role(realm.id, client_id);
    let role_name = role.name.clone();

    // Create the role
    state.role_provider.create(&role).await.map_err(|e| {
        if e.is_duplicate() {
            AdminError::conflict("Role", "name", &role_name)
        } else {
            AdminError::from(e)
        }
    })?;

    // Return 201 Created with Location header
    Ok((
        StatusCode::CREATED,
        [(
            "Location",
            format!(
                "/admin/realms/{}/clients/{}/roles/{}",
                realm_name, client_id, role_name
            ),
        )],
    ))
}

/// GET /admin/realms/{realm}/clients/{id}/roles/{role-name} - Get client role by name
async fn get_client_role<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, client_id, role_name)): Path<(String, uuid::Uuid, String)>,
) -> AdminResult<Json<RoleRepresentation>>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Validate client exists
    if state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .is_none()
    {
        return Err(AdminError::not_found_id("Client", client_id));
    }

    // Get role
    let role = state
        .role_provider
        .get_client_role_by_name(realm.id, client_id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    Ok(Json(RoleRepresentation::from(role)))
}

/// PUT /admin/realms/{realm}/clients/{id}/roles/{role-name} - Update a client role
async fn update_client_role<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, client_id, role_name)): Path<(String, uuid::Uuid, String)>,
    Json(request): Json<UpdateRoleRequest>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Validate client exists
    if state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .is_none()
    {
        return Err(AdminError::not_found_id("Client", client_id));
    }

    // Get existing role
    let mut role = state
        .role_provider
        .get_client_role_by_name(realm.id, client_id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    // Check for name conflict if changing name
    if let Some(ref new_name) = request.name {
        if new_name != &role.name {
            if state
                .role_provider
                .get_client_role_by_name(realm.id, client_id, new_name)
                .await?
                .is_some()
            {
                return Err(AdminError::conflict("Role", "name", new_name));
            }
        }
    }

    // Apply updates
    request.apply_to(&mut role);

    // Save updates
    state.role_provider.update(&role).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/realms/{realm}/clients/{id}/roles/{role-name} - Delete a client role
async fn delete_client_role<R, C, Ro>(
    State(state): State<RoleState<R, C, Ro>>,
    Path((realm_name, client_id, role_name)): Path<(String, uuid::Uuid, String)>,
) -> AdminResult<impl IntoResponse>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    // Validate realm exists
    let realm = state
        .realm_provider
        .get_by_name(&realm_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Realm", &realm_name))?;

    // Validate client exists
    if state
        .client_provider
        .get_by_id(realm.id, client_id)
        .await?
        .is_none()
    {
        return Err(AdminError::not_found_id("Client", client_id));
    }

    // Get role to get its ID
    let role = state
        .role_provider
        .get_client_role_by_name(realm.id, client_id, &role_name)
        .await?
        .ok_or_else(|| AdminError::not_found("Role", &role_name))?;

    // Delete the role
    state.role_provider.delete(realm.id, role.id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Router Construction
// ============================================================================

/// Creates the Admin API router for user operations.
///
/// # Routes
///
/// ## Realms
/// - `GET /admin/realms` - List all realms
/// - `POST /admin/realms` - Create a new realm
/// - `GET /admin/realms/{realm}` - Get realm by name
/// - `PUT /admin/realms/{realm}` - Update a realm
/// - `DELETE /admin/realms/{realm}` - Delete a realm
///
/// ## Users
/// - `GET /admin/realms/{realm}/users` - List/search users
/// - `POST /admin/realms/{realm}/users` - Create a user
/// - `GET /admin/realms/{realm}/users/{id}` - Get user by ID
/// - `PUT /admin/realms/{realm}/users/{id}` - Update a user
/// - `DELETE /admin/realms/{realm}/users/{id}` - Delete a user
///
/// # Example
///
/// ```ignore
/// use kc_admin_api::{admin_router, UserState};
/// use std::sync::Arc;
///
/// let state = UserState::new(
///     Arc::new(realm_provider),
///     Arc::new(user_provider),
///     Arc::new(credential_provider),
/// );
///
/// let app = admin_router().with_state(state);
/// ```
pub fn admin_router<R, U, Cr>() -> Router<UserState<R, U, Cr>>
where
    R: RealmProvider + 'static,
    U: UserProvider + 'static,
    Cr: CredentialProvider + 'static,
{
    Router::new()
        // Realm endpoints
        .route("/admin/realms", get(list_realms::<R, U, Cr>))
        .route("/admin/realms", post(create_realm::<R, U, Cr>))
        .route("/admin/realms/{realm}", get(get_realm::<R, U, Cr>))
        .route("/admin/realms/{realm}", put(update_realm::<R, U, Cr>))
        .route("/admin/realms/{realm}", delete(delete_realm::<R, U, Cr>))
        // User endpoints
        .route("/admin/realms/{realm}/users", get(get_users::<R, U, Cr>))
        .route("/admin/realms/{realm}/users", post(create_user::<R, U, Cr>))
        .route(
            "/admin/realms/{realm}/users/{id}",
            get(get_user::<R, U, Cr>),
        )
        .route(
            "/admin/realms/{realm}/users/{id}",
            put(update_user::<R, U, Cr>),
        )
        .route(
            "/admin/realms/{realm}/users/{id}",
            delete(delete_user::<R, U, Cr>),
        )
}

/// Creates the Admin API router for client operations.
///
/// # Routes
///
/// ## Clients
/// - `GET /admin/realms/{realm}/clients` - List/search clients
/// - `POST /admin/realms/{realm}/clients` - Create a client
/// - `GET /admin/realms/{realm}/clients/{id}` - Get client by ID
/// - `PUT /admin/realms/{realm}/clients/{id}` - Update a client
/// - `DELETE /admin/realms/{realm}/clients/{id}` - Delete a client
/// - `GET /admin/realms/{realm}/clients/{id}/client-secret` - Get client secret
/// - `POST /admin/realms/{realm}/clients/{id}/client-secret` - Regenerate client secret
///
/// # Example
///
/// ```ignore
/// use kc_admin_api::{admin_client_router, ClientState};
/// use std::sync::Arc;
///
/// let state = ClientState::new(
///     Arc::new(realm_provider),
///     Arc::new(client_provider),
/// );
///
/// let app = admin_client_router().with_state(state);
/// ```
pub fn admin_client_router<R, C>() -> Router<ClientState<R, C>>
where
    R: RealmProvider + 'static,
    C: ClientProvider + 'static,
{
    Router::new()
        .route("/admin/realms/{realm}/clients", get(get_clients::<R, C>))
        .route("/admin/realms/{realm}/clients", post(create_client::<R, C>))
        .route(
            "/admin/realms/{realm}/clients/{id}",
            get(get_client::<R, C>),
        )
        .route(
            "/admin/realms/{realm}/clients/{id}",
            put(update_client::<R, C>),
        )
        .route(
            "/admin/realms/{realm}/clients/{id}",
            delete(delete_client::<R, C>),
        )
        .route(
            "/admin/realms/{realm}/clients/{id}/client-secret",
            get(get_client_secret::<R, C>),
        )
        .route(
            "/admin/realms/{realm}/clients/{id}/client-secret",
            post(regenerate_client_secret::<R, C>),
        )
}

/// Creates a standalone realm router (for modular composition).
///
/// # Routes
///
/// - `GET /` - List all realms
/// - `POST /` - Create a new realm
/// - `GET /{realm}` - Get realm by name
/// - `PUT /{realm}` - Update a realm
/// - `DELETE /{realm}` - Delete a realm
pub fn realm_router<R, U, Cr>() -> Router<UserState<R, U, Cr>>
where
    R: RealmProvider + 'static,
    U: UserProvider + 'static,
    Cr: CredentialProvider + 'static,
{
    Router::new()
        .route("/", get(list_realms::<R, U, Cr>))
        .route("/", post(create_realm::<R, U, Cr>))
        .route("/{realm}", get(get_realm::<R, U, Cr>))
        .route("/{realm}", put(update_realm::<R, U, Cr>))
        .route("/{realm}", delete(delete_realm::<R, U, Cr>))
}

/// Creates a standalone user router (for modular composition).
///
/// Note: This router expects to be nested under a path that includes the realm,
/// e.g., `/admin/realms/{realm}/users`.
///
/// # Routes
///
/// - `GET /` - List/search users
/// - `POST /` - Create a user
/// - `GET /{id}` - Get user by ID
/// - `PUT /{id}` - Update a user
/// - `DELETE /{id}` - Delete a user
pub fn user_router<R, U, Cr>() -> Router<UserState<R, U, Cr>>
where
    R: RealmProvider + 'static,
    U: UserProvider + 'static,
    Cr: CredentialProvider + 'static,
{
    Router::new()
        .route("/", get(get_users::<R, U, Cr>))
        .route("/", post(create_user::<R, U, Cr>))
        .route("/{id}", get(get_user::<R, U, Cr>))
        .route("/{id}", put(update_user::<R, U, Cr>))
        .route("/{id}", delete(delete_user::<R, U, Cr>))
}

/// Creates a standalone client router (for modular composition).
///
/// Note: This router expects to be nested under a path that includes the realm,
/// e.g., `/admin/realms/{realm}/clients`.
///
/// # Routes
///
/// - `GET /` - List/search clients
/// - `POST /` - Create a client
/// - `GET /{id}` - Get client by ID
/// - `PUT /{id}` - Update a client
/// - `DELETE /{id}` - Delete a client
/// - `GET /{id}/client-secret` - Get client secret
/// - `POST /{id}/client-secret` - Regenerate client secret
pub fn client_router<R, C>() -> Router<ClientState<R, C>>
where
    R: RealmProvider + 'static,
    C: ClientProvider + 'static,
{
    Router::new()
        .route("/", get(get_clients::<R, C>))
        .route("/", post(create_client::<R, C>))
        .route("/{id}", get(get_client::<R, C>))
        .route("/{id}", put(update_client::<R, C>))
        .route("/{id}", delete(delete_client::<R, C>))
        .route("/{id}/client-secret", get(get_client_secret::<R, C>))
        .route("/{id}/client-secret", post(regenerate_client_secret::<R, C>))
}

/// Creates the Admin API router for role operations.
///
/// # Routes
///
/// ## Realm Roles
/// - `GET /admin/realms/{realm}/roles` - List realm roles
/// - `POST /admin/realms/{realm}/roles` - Create a realm role
/// - `GET /admin/realms/{realm}/roles/{role-name}` - Get realm role by name
/// - `PUT /admin/realms/{realm}/roles/{role-name}` - Update a realm role
/// - `DELETE /admin/realms/{realm}/roles/{role-name}` - Delete a realm role
/// - `GET /admin/realms/{realm}/roles/{role-name}/composites` - Get composite roles
/// - `POST /admin/realms/{realm}/roles/{role-name}/composites` - Add composite roles
/// - `DELETE /admin/realms/{realm}/roles/{role-name}/composites` - Remove composite roles
///
/// ## Client Roles
/// - `GET /admin/realms/{realm}/clients/{id}/roles` - List client roles
/// - `POST /admin/realms/{realm}/clients/{id}/roles` - Create a client role
/// - `GET /admin/realms/{realm}/clients/{id}/roles/{role-name}` - Get client role by name
/// - `PUT /admin/realms/{realm}/clients/{id}/roles/{role-name}` - Update a client role
/// - `DELETE /admin/realms/{realm}/clients/{id}/roles/{role-name}` - Delete a client role
///
/// # Example
///
/// ```ignore
/// use kc_admin_api::{admin_role_router, RoleState};
/// use std::sync::Arc;
///
/// let state = RoleState::new(
///     Arc::new(realm_provider),
///     Arc::new(client_provider),
///     Arc::new(role_provider),
/// );
///
/// let app = admin_role_router().with_state(state);
/// ```
pub fn admin_role_router<R, C, Ro>() -> Router<RoleState<R, C, Ro>>
where
    R: RealmProvider + 'static,
    C: ClientProvider + 'static,
    Ro: RoleProvider + 'static,
{
    Router::new()
        // Realm role endpoints
        .route(
            "/admin/realms/{realm}/roles",
            get(get_realm_roles::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/roles",
            post(create_realm_role::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/roles/{role_name}",
            get(get_realm_role::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/roles/{role_name}",
            put(update_realm_role::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/roles/{role_name}",
            delete(delete_realm_role::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/roles/{role_name}/composites",
            get(get_realm_role_composites::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/roles/{role_name}/composites",
            post(add_realm_role_composites::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/roles/{role_name}/composites",
            delete(remove_realm_role_composites::<R, C, Ro>),
        )
        // Client role endpoints
        .route(
            "/admin/realms/{realm}/clients/{client_id}/roles",
            get(get_client_roles::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/clients/{client_id}/roles",
            post(create_client_role::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/clients/{client_id}/roles/{role_name}",
            get(get_client_role::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/clients/{client_id}/roles/{role_name}",
            put(update_client_role::<R, C, Ro>),
        )
        .route(
            "/admin/realms/{realm}/clients/{client_id}/roles/{role_name}",
            delete(delete_client_role::<R, C, Ro>),
        )
}

/// Creates a standalone realm role router (for modular composition).
///
/// Note: This router expects to be nested under a path that includes the realm,
/// e.g., `/admin/realms/{realm}/roles`.
///
/// # Routes
///
/// - `GET /` - List realm roles
/// - `POST /` - Create a realm role
/// - `GET /{role-name}` - Get realm role by name
/// - `PUT /{role-name}` - Update a realm role
/// - `DELETE /{role-name}` - Delete a realm role
/// - `GET /{role-name}/composites` - Get composite roles
/// - `POST /{role-name}/composites` - Add composite roles
/// - `DELETE /{role-name}/composites` - Remove composite roles
pub fn realm_role_router<R, C, Ro>() -> Router<RoleState<R, C, Ro>>
where
    R: RealmProvider + 'static,
    C: ClientProvider + 'static,
    Ro: RoleProvider + 'static,
{
    Router::new()
        .route("/", get(get_realm_roles::<R, C, Ro>))
        .route("/", post(create_realm_role::<R, C, Ro>))
        .route("/{role_name}", get(get_realm_role::<R, C, Ro>))
        .route("/{role_name}", put(update_realm_role::<R, C, Ro>))
        .route("/{role_name}", delete(delete_realm_role::<R, C, Ro>))
        .route(
            "/{role_name}/composites",
            get(get_realm_role_composites::<R, C, Ro>),
        )
        .route(
            "/{role_name}/composites",
            post(add_realm_role_composites::<R, C, Ro>),
        )
        .route(
            "/{role_name}/composites",
            delete(remove_realm_role_composites::<R, C, Ro>),
        )
}

/// Creates a standalone client role router (for modular composition).
///
/// Note: This router expects to be nested under a path that includes the realm
/// and client, e.g., `/admin/realms/{realm}/clients/{id}/roles`.
///
/// # Routes
///
/// - `GET /` - List client roles
/// - `POST /` - Create a client role
/// - `GET /{role-name}` - Get client role by name
/// - `PUT /{role-name}` - Update a client role
/// - `DELETE /{role-name}` - Delete a client role
pub fn client_role_router<R, C, Ro>() -> Router<RoleState<R, C, Ro>>
where
    R: RealmProvider + 'static,
    C: ClientProvider + 'static,
    Ro: RoleProvider + 'static,
{
    Router::new()
        .route("/", get(get_client_roles::<R, C, Ro>))
        .route("/", post(create_client_role::<R, C, Ro>))
        .route("/{role_name}", get(get_client_role::<R, C, Ro>))
        .route("/{role_name}", put(update_client_role::<R, C, Ro>))
        .route("/{role_name}", delete(delete_client_role::<R, C, Ro>))
}

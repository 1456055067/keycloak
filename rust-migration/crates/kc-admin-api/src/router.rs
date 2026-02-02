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
use kc_storage::{CredentialProvider, RealmProvider, UserProvider};

use crate::dto::{
    CreateRealmRequest, CreateUserRequest, RealmRepresentation, RealmSummary,
    UpdateRealmRequest, UpdateUserRequest, UserRepresentation, UserSearchParams,
};
use crate::error::{AdminError, AdminResult};
use crate::state::UserState;

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
// Router Construction
// ============================================================================

/// Creates the Admin API router.
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

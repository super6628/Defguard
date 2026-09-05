use super::*;

#[sqlx::test]
async fn test_rule_rejects_empty_manual_location_scope(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let mut rule = make_rule();
    rule.all_locations = false;
    rule.locations.clear();

    let response = client.post("/api/v1/acl/rule").json(&rule).send().await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn test_rule_rejects_contradictory_all_source_flags(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let mut user_rule = make_rule();
    user_rule.allow_all_users = true;
    user_rule.deny_all_users = true;
    let response = client
        .post("/api/v1/acl/rule")
        .json(&user_rule)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut group_rule = make_rule();
    group_rule.allow_all_groups = true;
    group_rule.deny_all_groups = true;
    let response = client
        .post("/api/v1/acl/rule")
        .json(&group_rule)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut device_rule = make_rule();
    device_rule.allow_all_network_devices = true;
    device_rule.deny_all_network_devices = true;
    let response = client
        .post("/api/v1/acl/rule")
        .json(&device_rule)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn test_rule_rejects_explicit_allow_deny_collisions(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let mut user_rule = make_rule();
    user_rule.denied_users = user_rule.allowed_users.clone();
    let response = client
        .post("/api/v1/acl/rule")
        .json(&user_rule)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut group_rule = make_rule();
    group_rule.allowed_users.clear();
    group_rule.allowed_groups = vec![1];
    group_rule.denied_groups = vec![1];
    let response = client
        .post("/api/v1/acl/rule")
        .json(&group_rule)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut device_rule = make_rule();
    device_rule.allowed_users.clear();
    device_rule.allowed_network_devices = vec![1];
    device_rule.denied_network_devices = vec![1];
    let response = client
        .post("/api/v1/acl/rule")
        .json(&device_rule)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn test_acl_objects_reject_blank_names(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let mut rule = make_rule();
    rule.name = "   ".to_owned();
    let response = client.post("/api/v1/acl/rule").json(&rule).send().await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut alias = make_alias();
    alias.name = "   ".to_owned();
    let response = client.post("/api/v1/acl/alias").json(&alias).send().await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut destination = make_destination();
    destination.name = "   ".to_owned();
    let response = client
        .post("/api/v1/acl/destination")
        .json(&destination)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn test_acl_apply_endpoints_reject_empty_batches(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let response = client
        .put("/api/v1/acl/rule/apply")
        .json(&json!({ "rules": [] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = client
        .put("/api/v1/acl/alias/apply")
        .json(&json!({ "aliases": [] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = client
        .put("/api/v1/acl/destination/apply")
        .json(&json!({ "destinations": [] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn test_duplicate_rule_apply_rolls_back_batch(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let rule = make_rule();
    let response = client.post("/api/v1/acl/rule").json(&rule).send().await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: ApiAclRule = response.json().await;
    assert_eq!(created.state, RuleState::New);

    let response = client
        .put("/api/v1/acl/rule/apply")
        .json(&json!({ "rules": [created.id, created.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = client
        .get(format!("/api/v1/acl/rule/{}", created.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let persisted: ApiAclRule = response.json().await;
    assert_eq!(persisted.state, RuleState::New);
}

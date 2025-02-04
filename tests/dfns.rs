#[cfg(test)]
mod e2e {
    use blueprint_sdk::logging::setup_log;
    use blueprint_sdk::testing::tempfile::TempDir;
    use blueprint_sdk::testing::utils::harness::TestHarness;
    use blueprint_sdk::testing::utils::runner::TestEnv;
    use blueprint_sdk::testing::utils::tangle::{InputValue, OutputValue, TangleTestHarness};
    use blueprint_sdk::tokio;
    use dfns_cggmp21_blueprint::context::DfnsContext;
    use dfns_cggmp21_blueprint::key_refresh::KeyRefreshEventHandler;
    use dfns_cggmp21_blueprint::keygen::KeygenEventHandler;
    use dfns_cggmp21_blueprint::signing::SignEventHandler;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_blueprint() {
        setup_log();

        // Initialize test harness (node, keys, deployment)
        let temp_dir = TempDir::new()?;
        let harness = TangleTestHarness::setup(temp_dir).await?;
        let env = harness.env().clone();

        // Create blueprint-specific context
        let blueprint_ctx = DfnsContext::new(env.clone()).unwrap();

        // Initialize event handlers
        let keygen_handler = KeygenEventHandler::new(&env, blueprint_ctx.clone())
            .await
            .unwrap();
        let key_refresh_handler = KeyRefreshEventHandler::new(&env, blueprint_ctx.clone())
            .await
            .unwrap();
        let signing_handler = SignEventHandler::new(&env, blueprint_ctx.clone())
            .await
            .unwrap();

        // Setup service
        let (mut test_env, service_id) = harness.setup_services().await?;
        test_env.add_job(keygen_handler);
        test_env.add_job(key_refresh_handler);
        test_env.add_job(signing_handler);

        tokio::spawn(async move {
            test_env.run_runner().await.unwrap();
        });

        // Execute job and verify result
        let results = harness
            .execute_job(
                service_id,
                0,
                vec![InputValue::Uint64(2)],
                vec![OutputValue::Uint64(2)],
            )
            .await?;

        // // Execute job and verify result
        // let results = harness
        //     .execute_job(
        //         service_id,
        //         0,
        //         vec![InputValue::Uint64(5)],
        //         vec![OutputValue::Uint64(25)],
        //     )
        //     .await?;
        //
        // assert_eq!(results.service_id, service_id);
        //
        //
        //
        // let tmp_dir = TempDir::new().unwrap();
        // let tmp_dir_path = format!("{}", tmp_dir.path().display());
        //
        // new_test_ext_blueprint_manager::<N, 1, String, _, _>(
        //     tmp_dir_path,
        //     run_test_blueprint_manager,
        //     NodeConfig::new(false),
        // )
        //     .await
        //     .execute_with_async(|client, handles, blueprint, _| async move {
        //         let keypair = handles[0].sr25519_id().clone();
        //         let service = &blueprint.services[0];
        //
        //         let service_id = service.id;
        //         info!(
        //     "Submitting KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id}",
        // );
        //
        //         let job_args = vec![InputValue::Uint16(T as u16)];
        //         let call_id = get_next_call_id(client)
        //             .await
        //             .expect("Failed to get next job id")
        //             .saturating_sub(1);
        //
        //         let job = submit_job(
        //             client,
        //             &keypair,
        //             service_id,
        //             Job::from(KEYGEN_JOB_ID),
        //             job_args,
        //             call_id,
        //         )
        //             .await
        //             .expect("Failed to submit job");
        //
        //         let keygen_call_id = job.call_id;
        //
        //         info!(
        //     "Submitted KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id} has call id {keygen_call_id}",
        // );
        //
        //         let job_results = wait_for_completion_of_tangle_job(client, service_id, keygen_call_id, T + 1)
        //             .await
        //             .expect("Failed to wait for job completion");
        //
        //         assert_eq!(job_results.service_id, service_id);
        //         assert_eq!(job_results.call_id, keygen_call_id);
        //
        //         info!("Keygen job completed successfully! Moving on to key refresh ...");
        //
        //         // Key refresh
        //
        //         let service = &blueprint.services[0];
        //         let service_id = service.id;
        //         info!(
        //             "Submitting Key Refresh job {KEY_REFRESH_JOB_ID} with service ID {service_id}",
        //         );
        //
        //         let job_args = vec![
        //             InputValue::Uint64(keygen_call_id),
        //         ];
        //
        //         let job = submit_job(
        //             client,
        //             &keypair,
        //             service_id,
        //             Job::from(KEY_REFRESH_JOB_ID),
        //             job_args,
        //             keygen_call_id + 1,
        //         )
        //             .await
        //             .expect("Failed to submit job");
        //
        //         let key_refresh_call_id = job.call_id;
        //         info!(
        //     "Submitted KEY REFRESH job {SIGN_JOB_ID} with service ID {service_id} has call id {key_refresh_call_id}",
        // );
        //
        //         let job_results = wait_for_completion_of_tangle_job(client, service_id, key_refresh_call_id, T + 1)
        //             .await
        //             .expect("Failed to wait for job completion");
        //         assert_eq!(job_results.service_id, service_id);
        //         assert_eq!(job_results.call_id, key_refresh_call_id);
        //
        //         // Signing
        //
        //         let service = &blueprint.services[0];
        //         let service_id = service.id;
        //         info!(
        //             "Submitting SIGNING job {SIGN_JOB_ID} with service ID {service_id}",
        //         );
        //
        //         let job_args = vec![
        //             InputValue::Uint64(keygen_call_id),
        //             InputValue::List(BoundedVec(vec![
        //                 InputValue::Uint8(1),
        //                 InputValue::Uint8(2),
        //                 InputValue::Uint8(3),
        //             ])),
        //         ];
        //
        //         let job = submit_job(
        //             client,
        //             &keypair,
        //             service_id,
        //             Job::from(SIGN_JOB_ID),
        //             job_args,
        //             key_refresh_call_id + 1,
        //         )
        //             .await
        //             .expect("Failed to submit job");
        //
        //         let signing_call_id = job.call_id;
        //         info!(
        //             "Submitted SIGNING job {SIGN_JOB_ID} with service ID {service_id} has call id {signing_call_id}",
        //         );
        //
        //         let job_results = wait_for_completion_of_tangle_job(client, service_id, signing_call_id, T + 1)
        //             .await
        //             .expect("Failed to wait for job completion");
        //         assert_eq!(job_results.service_id, service_id);
        //         assert_eq!(job_results.call_id, signing_call_id);
        //     })
        //     .await
    }
}

#[cfg(test)]
mod e2e {
    use api::runtime_types::tangle_primitives::services::field::Field;
    use blueprint_test_utils::test_ext::*;
    use blueprint_test_utils::*;
    use dfns_cggmp21_blueprint::keygen::KEYGEN_JOB_ID;
    use gadget_sdk::error;
    use gadget_sdk::info;
    use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api;

    pub fn setup_testing_log() {
        use tracing_subscriber::util::SubscriberInitExt;
        let env_filter = tracing_subscriber::EnvFilter::from_default_env();
        let _ = tracing_subscriber::fmt::SubscriberBuilder::default()
            .without_time()
            .with_target(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
            .with_env_filter(env_filter)
            .with_test_writer()
            .finish()
            .try_init();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::needless_return)]
    async fn keygen() {
        setup_testing_log();
        const N: usize = 3;
        new_test_ext_blueprint_manager::<N, 1, _, _, _>("", run_test_blueprint_manager)
            .await
            .execute_with_async(move |client, handles, svcs| async move {
                // At this point, blueprint has been deployed, every node has registered
                // as an operator for the relevant services, and, all gadgets are running
                println!("Blueprint deployed and nodes registered");

                let keypair = handles[0].sr25519_id().clone();
                let service = &svcs.services[KEYGEN_JOB_ID as usize];
                println!("Got keypair and service");

                let service_id = service.id;
                let call_id = get_next_call_id(client)
                    .await
                    .expect("Failed to get next job id")
                    .saturating_sub(1);

                println!("Service ID: {}, Call ID: {}", service_id, call_id);
                info!("Submitting job with params service ID: {service_id}, call ID: {call_id}");

                // Pass the arguments
                let n = Field::Uint16(N as u16);
                let job_args = vec![n];
                println!("Created job arguments with N={}", N);

                // Next step: submit a job under that service/job id
                println!("Submitting job...");
                if let Err(err) = submit_job(
                    client,
                    &keypair,
                    service_id,
                    KEYGEN_JOB_ID,
                    job_args,
                    call_id,
                )
                .await
                {
                    error!("Failed to submit job: {err}");
                    panic!("Failed to submit job: {err}");
                }
                println!("Job submitted successfully");

                // Step 2: wait for the job to complete
                println!("Waiting for job completion...");
                let job_results =
                    wait_for_completion_of_tangle_job(client, service_id, call_id, N - 1)
                        .await
                        .expect("Failed to wait for job completion");
                println!("Job completed");

                // Step 3: Get the job results, compare to expected value(s)
                println!("Verifying job results...");
                assert_eq!(job_results.service_id, service_id);
                assert_eq!(job_results.call_id, call_id);
                assert!(matches!(job_results.result[0], Field::Bytes(_)));
            })
            .await;
    }
}

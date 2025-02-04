use blueprint_sdk::crypto::tangle_pair_signer::sp_core::Pair;
use blueprint_sdk::logging::info;
use blueprint_sdk::runners::core::runner::BlueprintRunner;
use blueprint_sdk::runners::tangle::tangle::TangleConfig;
use color_eyre::Result;
use dfns_cggmp21_blueprint::context::DfnsContext;

#[blueprint_sdk::main(env)]
async fn main() {
    let context = DfnsContext::new(env.clone())?;

    info!(
        "Starting the Blueprint Runner for {} ...",
        hex::encode(context.identity.public().as_ref())
    );

    info!("~~~ Executing the DFNS-CGGMP21 blueprint ~~~");

    let tangle_config = TangleConfig::default();
    let keygen =
        dfns_cggmp21_blueprint::keygen::KeygenEventHandler::new(&env, context.clone()).await?;

    let key_refresh =
        dfns_cggmp21_blueprint::key_refresh::KeyRefreshEventHandler::new(&env, context.clone())
            .await?;

    let signing =
        dfns_cggmp21_blueprint::signing::SignEventHandler::new(&env, context.clone()).await?;

    BlueprintRunner::new(tangle_config, env.clone())
        .job(keygen)
        .job(key_refresh)
        .job(signing)
        .run()
        .await?;

    info!("Exiting...");
    Ok(())
}

use serial_test::serial;
use ucs_connector_tests::harness::{context::FlowContext, executor::AuthorizedotnetExecutor};

use crate::authorizedotnet::suites::{
    authorize, capture, create_customer, generated_input_variants, get, refund, void,
};

#[derive(Clone, Copy)]
enum CompositeStep {
    CreateCustomer,
    AuthorizeManual,
    AuthorizeAuto,
    Capture,
    Get,
    Void,
    Refund,
}

async fn run_step_variants(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    step: CompositeStep,
    base_context: &FlowContext,
) -> Option<FlowContext> {
    let mut default_context_for_next_step: Option<FlowContext> = None;

    match step {
        CompositeStep::CreateCustomer => {
            let default_scenario = create_customer::default_scenario();
            for variant in create_customer::variants() {
                let mut context = base_context.clone();
                create_customer::execute(executor, flow_name, &mut context, *variant).await;
                if *variant == default_scenario {
                    default_context_for_next_step = Some(context);
                }
            }
        }
        CompositeStep::AuthorizeManual | CompositeStep::AuthorizeAuto => {
            let default_scenario = match step {
                CompositeStep::AuthorizeManual => authorize::default_manual_scenario(),
                CompositeStep::AuthorizeAuto => authorize::default_auto_scenario(),
                _ => unreachable!(),
            };

            for variant in authorize::variants() {
                let mut context = base_context.clone();
                authorize::execute(executor, flow_name, &mut context, *variant).await;
                if *variant == default_scenario {
                    default_context_for_next_step = Some(context);
                }
            }
        }
        CompositeStep::Capture => {
            let default_scenario = capture::default_scenario();
            for variant in capture::variants() {
                let mut context = base_context.clone();
                capture::execute(executor, flow_name, &mut context, *variant).await;
                if *variant == default_scenario {
                    default_context_for_next_step = Some(context);
                }
            }
        }
        CompositeStep::Get => {
            let default_scenario = get::default_scenario();
            for variant in get::variants() {
                let mut context = base_context.clone();
                get::execute(executor, flow_name, &mut context, *variant).await;
                if *variant == default_scenario {
                    default_context_for_next_step = Some(context);
                }
            }
        }
        CompositeStep::Void => {
            let default_scenario = void::default_scenario();
            for variant in void::variants() {
                let mut context = base_context.clone();
                void::execute(executor, flow_name, &mut context, *variant).await;
                if *variant == default_scenario {
                    default_context_for_next_step = Some(context);
                }
            }
        }
        CompositeStep::Refund => {
            let default_scenario = refund::default_scenario();
            for variant in refund::variants() {
                let mut context = base_context.clone();
                refund::execute(executor, flow_name, &mut context, *variant).await;
                if *variant == default_scenario {
                    default_context_for_next_step = Some(context);
                }
            }
        }
    }

    default_context_for_next_step
}

async fn run_step_default(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    step: CompositeStep,
    context: &mut FlowContext,
) {
    match step {
        CompositeStep::CreateCustomer => {
            create_customer::execute(
                executor,
                flow_name,
                context,
                create_customer::default_scenario(),
            )
            .await
        }
        CompositeStep::AuthorizeManual => {
            authorize::execute(
                executor,
                flow_name,
                context,
                authorize::default_manual_scenario(),
            )
            .await
        }
        CompositeStep::AuthorizeAuto => {
            authorize::execute(
                executor,
                flow_name,
                context,
                authorize::default_auto_scenario(),
            )
            .await
        }
        CompositeStep::Capture => {
            capture::execute(executor, flow_name, context, capture::default_scenario()).await
        }
        CompositeStep::Get => {
            get::execute(executor, flow_name, context, get::default_scenario()).await
        }
        CompositeStep::Void => {
            void::execute(executor, flow_name, context, void::default_scenario()).await
        }
        CompositeStep::Refund => {
            refund::execute(executor, flow_name, context, refund::default_scenario()).await
        }
    }
}

async fn run_progressive_composite_flow(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    steps: &[CompositeStep],
) {
    for case in generated_input_variants() {
        let mut default_context: Option<FlowContext> = None;

        for (index, step) in steps.iter().enumerate() {
            let is_last_step = index == steps.len() - 1;
            let base_context = if index == 0 {
                FlowContext::new(case.clone(), flow_name)
            } else {
                default_context
                    .clone()
                    .expect("default context should exist for dependent step")
            };

            let default_from_variants =
                run_step_variants(executor, flow_name, *step, &base_context).await;

            if !is_last_step {
                if let Some(variant_default_context) = default_from_variants {
                    default_context = Some(variant_default_context);
                } else {
                    let mut next_default = base_context;
                    run_step_default(executor, flow_name, *step, &mut next_default).await;
                    default_context = Some(next_default);
                }
            }
        }
    }
}

/// @capability capability_id=ANET-CAP-012
/// @capability connector=authorizedotnet
/// @capability layer=composite
/// @capability flow=composite_5_steps
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=create_customer_then_authorize_manual_then_capture_then_get_then_refund
/// @capability support=progressive
/// @capability expected=all_step_variants_with_default_carry_forward
#[tokio::test]
#[serial]
async fn test_authorizedotnet__composite_progressive__5_steps__create_customer_then_authorize_manual_then_capture_then_get_then_refund__runs_all_step_variants_with_default_carry_forward(
) {
    let executor = AuthorizedotnetExecutor::new().await;
    run_progressive_composite_flow(
        &executor,
        "composite_5_step",
        &[
            CompositeStep::CreateCustomer,
            CompositeStep::AuthorizeManual,
            CompositeStep::Capture,
            CompositeStep::Get,
            CompositeStep::Refund,
        ],
    )
    .await;
}

/// @capability capability_id=ANET-CAP-013
/// @capability connector=authorizedotnet
/// @capability layer=composite
/// @capability flow=composite_4_steps
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=create_customer_then_authorize_manual_then_capture_then_refund
/// @capability support=progressive
/// @capability expected=all_step_variants_with_default_carry_forward
#[tokio::test]
#[serial]
async fn test_authorizedotnet__composite_progressive__4_steps__create_customer_then_authorize_manual_then_capture_then_refund__runs_all_step_variants_with_default_carry_forward(
) {
    let executor = AuthorizedotnetExecutor::new().await;
    run_progressive_composite_flow(
        &executor,
        "composite_4_step",
        &[
            CompositeStep::CreateCustomer,
            CompositeStep::AuthorizeManual,
            CompositeStep::Capture,
            CompositeStep::Refund,
        ],
    )
    .await;
}

/// @capability capability_id=ANET-CAP-014
/// @capability connector=authorizedotnet
/// @capability layer=composite
/// @capability flow=composite_3_steps
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=create_customer_then_authorize_manual_then_void
/// @capability support=progressive
/// @capability expected=all_step_variants_with_default_carry_forward
#[tokio::test]
#[serial]
async fn test_authorizedotnet__composite_progressive__3_steps__create_customer_then_authorize_manual_then_void__runs_all_step_variants_with_default_carry_forward(
) {
    let executor = AuthorizedotnetExecutor::new().await;
    run_progressive_composite_flow(
        &executor,
        "composite_3_step",
        &[
            CompositeStep::CreateCustomer,
            CompositeStep::AuthorizeManual,
            CompositeStep::Void,
        ],
    )
    .await;
}

/// @capability capability_id=ANET-CAP-015
/// @capability connector=authorizedotnet
/// @capability layer=composite
/// @capability flow=composite_2_steps
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=create_customer_then_authorize_auto
/// @capability support=progressive
/// @capability expected=all_step_variants_with_default_carry_forward
#[tokio::test]
#[serial]
async fn test_authorizedotnet__composite_progressive__2_steps__create_customer_then_authorize_auto__runs_all_step_variants_with_default_carry_forward(
) {
    let executor = AuthorizedotnetExecutor::new().await;
    run_progressive_composite_flow(
        &executor,
        "composite_2_step",
        &[CompositeStep::CreateCustomer, CompositeStep::AuthorizeAuto],
    )
    .await;
}

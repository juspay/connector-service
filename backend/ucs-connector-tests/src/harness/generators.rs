use proptest::{
    prelude::any,
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};

#[derive(Clone, Debug)]
pub struct GeneratedCase {
    pub amount_minor: i64,
    pub email: String,
    pub merchant_txn_id: String,
    pub request_id: String,
    pub connector_request_reference_id: String,
    pub first_name: String,
    pub last_name: String,
    pub line1: String,
    pub city: String,
    pub zip_code: String,
}

pub fn generate_cases(count: usize) -> Vec<GeneratedCase> {
    let strategy = (100_i64..5000_i64, any::<u32>(), any::<u32>(), any::<u16>()).prop_map(
        |(amount_minor, a, b, c)| GeneratedCase {
            amount_minor,
            email: format!("ucs.{a}.{b}@example.com"),
            merchant_txn_id: format!("ucs_authnet_{a}_{b}"),
            request_id: format!("req_{a}_{b}"),
            connector_request_reference_id: format!("conn_ref_{a}_{b}"),
            first_name: format!("User{}", c % 100),
            last_name: format!("Case{}", (c / 2) % 100),
            line1: format!("{} Main Street", 100 + (c % 900)),
            city: "Austin".to_string(),
            zip_code: format!("{:05}", 70000_u32 + u32::from(c % 999)),
        },
    );

    let mut runner = TestRunner::default();
    (0..count)
        .map(|_| {
            let tree = strategy
                .new_tree(&mut runner)
                .expect("strategy should generate test values");
            tree.current()
        })
        .collect()
}

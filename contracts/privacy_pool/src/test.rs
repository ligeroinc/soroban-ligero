#![cfg(test)]

use super::*;
use soroban_sdk::{Env, String, vec, testutils::Address as _};

#[test]
fn test() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(Contract, (owner,));
    let client = ContractClient::new(&env, &contract_id);
    let words = client.version();
    assert_eq!(
        words,
        vec![
            &env,
            String::from_str(&env, "Ligero Privacy Pool v4.0")
        ]
    );
}

#![cfg(test)]

use super::*;
use soroban_sdk::{Bytes, BytesN, Env, String, log, vec};
//use hex;


#[test]
fn test() {
    let env = Env::default();
    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_id);

    
    let words = client.version();
    assert_eq!(
        words,
        vec![
            &env,
            String::from_str(&env, "Ligero PayrollClear v1.0")
        ]
    );
    

    /* *
    let hex_str = "0x2701c191a56f6c758a256482aad93d24b8304c2f0467001b1b54ee7040f68042";

    let clean_hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes_vec = hex::decode(clean_hex).unwrap();
    let mut bytes_32: [u8; 32] = [0; 32];
    let start = 32 - bytes_vec.len().min(32);
    bytes_32[start..].copy_from_slice(&bytes_vec[..bytes_vec.len().min(32)]);

    let val = U256::from_be_bytes(&env, &Bytes::from_slice(&env, &bytes_32));
    let hash = client.hash_function_pair(&U256::from_u32(&env, 1), &U256::from_u32(&env, 2));

    log!(&env, "Value: {}", val);
    
    assert_eq!(hash, val);

    let mut leaves:Vec<U256> = Vec::new(&env);
    leaves.push_back(U256::from_u32(&env, 1));
    leaves.push_back(U256::from_u32(&env, 2));
    leaves.push_back(U256::from_u32(&env, 3));
    leaves.push_back(U256::from_u32(&env, 4));
    client.insert_leaves(&leaves);
     */

}

#![no_std]
use poseidon2_ligero::{poseidon2_hash_single, poseidon2_hash_pair};
use soroban_sdk::{Address, Env, String, Symbol, U256, Map, Vec, contract, contractimpl, symbol_short, token, vec};

#[contract]
pub struct Contract;

const HASHES: Symbol = symbol_short!("HASHES");
const ROOT: Symbol = symbol_short!("ROOT");
const LSIZE: Symbol = symbol_short!("LSIZE");
const NLEVELS: Symbol = symbol_short!("NLEVELS");
const EMPLOYER: Symbol = symbol_short!("EMPLOYER");
const EMPLOYEE: Symbol = symbol_short!("EMPLOYEE");
const ADMINS: Symbol = symbol_short!("ADMINS");
const OWNER: Symbol = symbol_short!("OWNER");
const RELAYER: Symbol = symbol_short!("RELAYER");
const ROOTS: Symbol = symbol_short!("ROOTS");

#[contractimpl]
impl Contract {

    pub fn __constructor(env: Env, owner: Address) {
        env.storage().instance().set(&OWNER, &owner);
        env.storage().instance().set(&RELAYER, &owner);

        let mut roots: Map<U256, bool> = Map::new(&env);
        roots.set(U256::from_u32(&env, 0), true);
        env.storage().instance().set(&ROOTS, &roots);
    }

    /* Contract admin operations */

    pub fn owner(env: Env) -> Address {
        env.storage()
            .instance()
            .get::<_, Address>(&OWNER)
            .unwrap()
    }

    pub fn transfer_ownership(env: &Env, new_owner: Address) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        env.storage().instance().set(&OWNER, &new_owner);
    }

    pub fn get_relayer(env: Env) -> Address {
        env.storage().instance().get(&RELAYER).unwrap()
    }

    pub fn set_relayer(env: &Env, new_relayer: Address) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        env.storage().instance().set(&RELAYER, &new_relayer);
    }

    pub fn add_admin(env: &Env, admin: Address) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();

        let mut admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(&env));
        admins_map.set(admin, true);
        env.storage().instance().set(&ADMINS, &admins_map);
    }

    pub fn remove_admin(env: &Env, admin: Address) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();

        let mut admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(&env));
        admins_map.set(admin, false);
        env.storage().instance().set(&ADMINS, &admins_map);
    }

    pub fn is_admin(env: Env, address: Address) -> bool {
        let admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(&env));
        admins_map.get(address).unwrap_or(false)
    }

    /* Whitelist operations */

    pub fn add_employer(env: &Env, admin: Address, employer_address: Address) {
        let admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(&env));
        let is_admin = admins_map.get(admin.clone()).unwrap_or(false);
        assert!(is_admin, "caller should be an admin");
        admin.require_auth();

        let mut employer_map: Map<Address, bool> = env.storage().instance().get(&EMPLOYER).unwrap_or(Map::new(&env));
        employer_map.set(employer_address, true);
        env.storage().instance().set(&EMPLOYER, &employer_map);
    }

    pub fn remove_employer(env: &Env, admin: Address, employer_address: Address) {
        let admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(&env));
        let is_admin = admins_map.get(admin.clone()).unwrap_or(false);
        assert!(is_admin, "caller should be an admin");
        admin.require_auth();

        let mut employer_map: Map<Address, bool> = env.storage().instance().get(&EMPLOYER).unwrap_or(Map::new(&env));
        employer_map.set(employer_address, false);
        env.storage().instance().set(&EMPLOYER, &employer_map);
    }

    pub fn is_employer(env: Env, address: Address) -> bool {
        let employer_map: Map<Address, bool> = env.storage().instance().get(&EMPLOYER).unwrap_or(Map::new(&env));
        employer_map.get(address).unwrap_or(false)
    }

    pub fn add_employee(env: &Env, admin: Address, employee_address: Address) {
        let admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(&env));
        let is_admin = admins_map.get(admin.clone()).unwrap_or(false);
        assert!(is_admin, "caller should be an admin");
        admin.require_auth();

        let mut employee_map: Map<Address, bool> = env.storage().instance().get(&EMPLOYEE).unwrap_or(Map::new(&env));
        employee_map.set(employee_address, true);
        env.storage().instance().set(&EMPLOYEE, &employee_map);
    }

    pub fn remove_employee(env: &Env, admin: Address, employee_address: Address) {
        let admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(&env));
        let is_admin = admins_map.get(admin.clone()).unwrap_or(false);
        assert!(is_admin, "caller should be an admin");
        admin.require_auth();

        let mut employee_map: Map<Address, bool> = env.storage().instance().get(&EMPLOYEE).unwrap_or(Map::new(&env));
        employee_map.set(employee_address, false);
        env.storage().instance().set(&EMPLOYEE, &employee_map);
    }

    pub fn is_employee(env: Env, address: Address) -> bool {
        let employee_map: Map<Address, bool> = env.storage().instance().get(&EMPLOYEE).unwrap_or(Map::new(&env));
        employee_map.get(address).unwrap_or(false)
    }

    /* Merkle tree operations */

    pub fn hash_function_u256(env: &Env, a: U256) -> U256 {
        poseidon2_hash_single(env, a)
    }

    pub fn hash_function_pair(env: &Env, a: U256, b: U256) -> U256 {
        poseidon2_hash_pair(env, a, b)
    }

    pub fn insert_leaf_hash(env: &Env, leaf: U256) {
        let mut merkle_tree: Vec<Vec<U256>> = env.storage().instance().get(&HASHES).unwrap_or(Vec::new(&env));
        let mut level_size: Vec<u32> = env.storage().instance().get(&LSIZE).unwrap_or(Vec::new(&env));
        let merkle_tree_root;
        let mut number_of_levels = env.storage().instance().get(&NLEVELS).unwrap_or(0);

        let dummy_value: U256 = U256::from_u32(env, 0);

        if level_size.len() == 0 {
            level_size.push_back(0);
            merkle_tree.push_back(Vec::new(&env));
            number_of_levels = 1;
        }

        let mut current_level: u32 = 0;
        let mut current_size = level_size.get_unchecked(0);

        if (current_size > 3) && (merkle_tree.get_unchecked(0).get_unchecked(current_size - 1) == dummy_value) {
            let mut level = merkle_tree.get_unchecked(0);
            level.set(current_size - 1, leaf);
            merkle_tree.set(0, level);
        } else {
            let mut level = merkle_tree.get_unchecked(0);
            level.push_back(leaf);
            merkle_tree.set(0, level);
            current_size += 1;
        }
        level_size.set(0, current_size);

        while current_size > 1 {
            if current_size % 2 != 0 {
                let mut level = merkle_tree.get_unchecked(current_level);
                level.push_back(dummy_value.clone());
                merkle_tree.set(current_level, level);
                current_size += 1;
                level_size.set(current_level, current_size);
            }
            if current_level + 1 >= number_of_levels {
                number_of_levels += 1;
            }

            let value_for_next_level = Self::hash_function_pair(env,
                merkle_tree.get_unchecked(current_level).get_unchecked(current_size - 2),
                merkle_tree.get_unchecked(current_level).get_unchecked(current_size - 1)
            );
            let index_to_update = (current_size + 1) / 2;

            if current_level + 1 < merkle_tree.len() {
                let mut set_level = merkle_tree.get_unchecked(current_level + 1);
                if index_to_update - 1 < set_level.len() {
                    set_level.set(index_to_update - 1, value_for_next_level);
                } else {
                    set_level.push_back(value_for_next_level);
                }
                merkle_tree.set(current_level + 1, set_level);
            } else {
                let mut new_level: Vec<U256> = Vec::new(&env);
                new_level.push_back(value_for_next_level);
                merkle_tree.push_back(new_level);
            }

            if current_level + 1 < level_size.len() {
                level_size.set(current_level + 1, index_to_update);
            } else {
                level_size.push_back(index_to_update);
            }
            level_size.set(current_level, current_size);

            current_level += 1;
            current_size = level_size.get_unchecked(current_level);
        }

        merkle_tree_root = merkle_tree.get_unchecked(number_of_levels - 1).get_unchecked(0);

        env.storage().instance().set(&HASHES, &merkle_tree);
        env.storage().instance().set(&LSIZE, &level_size);
        env.storage().instance().set(&ROOT, &merkle_tree_root);
        env.storage().instance().set(&NLEVELS, &number_of_levels);

        let mut roots: Map<U256, bool> = env.storage().instance().get(&ROOTS).unwrap_or(Map::new(&env));
        roots.set(merkle_tree_root, true);
        env.storage().instance().set(&ROOTS, &roots);
    }

    pub fn insert_leaves(env: &Env, leaves: Vec<U256>) {
        for leaf in leaves.iter() {
            let hash = Self::hash_function_u256(env, Self::hash_function_u256(env, leaf));
            Self::insert_leaf_hash(env, hash);
        }
    }

    pub fn get_hashes(env: &Env) -> Vec<Vec<U256>> {
        env.storage().instance().get(&HASHES).unwrap_or(Vec::new(&env))
    }

    pub fn get_number_of_levels(env: &Env) -> u32 {
        env.storage().instance().get(&NLEVELS).unwrap_or(0)
    }

    pub fn get_levels(env: &Env) -> Vec<u32> {
        env.storage().instance().get(&LSIZE).unwrap_or(Vec::new(&env))
    }

    pub fn get_root(env: &Env) -> U256 {
        env.storage().instance().get(&ROOT).unwrap_or(U256::from_u32(env, 0))
    }

    /* Main payroll functionality */

    pub fn disburse(env: Env, relayer: Address, note_commitments: Vec<U256>, token_address: Address, spender_address: Address, amount: i128, root: U256) {
        let employer_map: Map<Address, bool> = env.storage().instance().get(&EMPLOYER).unwrap_or(Map::new(&env));
        let is_employer = employer_map.get(spender_address.clone()).unwrap_or(false);
        assert!(is_employer, "spender should be an employer");

        let stored_relayer: Address = env.storage().instance().get(&RELAYER).unwrap();
        assert!(relayer == stored_relayer, "caller is not the relayer");
        relayer.require_auth();

        let roots: Map<U256, bool> = env.storage().instance().get(&ROOTS).unwrap_or(Map::new(&env));
        assert!(roots.get(root).unwrap_or(false), "Root verification failed");

        let token_client = token::Client::new(&env, &token_address);
        let to = env.current_contract_address();
        token_client.transfer_from(&relayer, &spender_address, &to, &amount);

        Self::insert_leaves(&env, note_commitments);
    }

    pub fn withdraw(
        env: Env,
        relayer: Address,
        note_commitments: Vec<U256>,
        receiver_address: Address,
        token_address: Address,
        amount: i128,
        root: U256,
    ) {
        let stored_relayer: Address = env.storage().instance().get(&RELAYER).unwrap();
        assert!(relayer == stored_relayer, "caller is not the relayer");
        relayer.require_auth();

        let employee_map: Map<Address, bool> = env.storage().instance().get(&EMPLOYEE).unwrap_or(Map::new(&env));
        let is_employee = employee_map.get(receiver_address.clone()).unwrap_or(false);
        assert!(is_employee, "receiver should be an employee");

        let roots: Map<U256, bool> = env.storage().instance().get(&ROOTS).unwrap_or(Map::new(&env));
        assert!(roots.get(root).unwrap_or(false), "Root verification failed");

        let from = env.current_contract_address();
        let token_client = token::Client::new(&env, &token_address);
        token_client.transfer(&from, &receiver_address, &amount);

        Self::insert_leaves(&env, note_commitments);
    }

    pub fn version(env: Env) -> Vec<String> {
        vec![&env, String::from_str(&env, "Ligero Payroll v1.0")]
    }
}

mod test;

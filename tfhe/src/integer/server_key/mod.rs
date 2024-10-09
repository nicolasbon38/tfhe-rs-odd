//! Module with the definition of the ServerKey.
//!
//! This module implements the generation of the server public key, together with all the
//! available homomorphic integer operations.
pub mod comparator;
mod crt;
mod crt_parallel;
mod radix;
pub(crate) mod radix_parallel;

use crate::integer::client_key::ClientKey;
use crate::shortint::ciphertext::MaxDegree;
use serde::{Deserialize, Serialize};

/// Error returned when the carry buffer is full.
pub use crate::shortint::CheckError;
use crate::shortint::{CarryModulus, MessageModulus};
pub use radix::scalar_mul::ScalarMultiplier;
pub use radix::scalar_sub::TwosComplementNegation;
pub use radix_parallel::{MiniUnsignedInteger, Reciprocable};

/// A structure containing the server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic integer circuits.
#[derive(Serialize, Deserialize, Clone)]
pub struct ServerKey {
    pub(crate) key: crate::shortint::ServerKey,
}

impl From<ServerKey> for crate::shortint::ServerKey {
    fn from(key: ServerKey) -> Self {
        key.key
    }
}

impl MaxDegree {
    /// Compute the [`MaxDegree`] for an integer server key (compressed or uncompressed).
    /// To allow carry propagation between shortint blocks in a
    /// [`RadixCiphertext`](`crate::integer::RadixCiphertext`) (which includes adding the extracted
    /// carry from one shortint block to the next block), this formula provisions space to add a
    /// carry.
    fn integer_radix_server_key(
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Self {
        let full_max_degree = message_modulus.0 * carry_modulus.0 - 1;

        let carry_max_degree = carry_modulus.0 - 1;

        // We want to be have a margin to add a carry from another block
        Self::new(full_max_degree - carry_max_degree)
    }
}

impl MaxDegree {
    /// Compute the [`MaxDegree`] for an integer server key (compressed or uncompressed).
    /// This is tailored for [`CrtCiphertext`](`crate::integer::CrtCiphertext`) and not compatible
    /// for use with [`RadixCiphertext`](`crate::integer::RadixCiphertext`).
    fn integer_crt_server_key(
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Self {
        let full_max_degree = message_modulus.0 * carry_modulus.0 - 1;

        Self::new(full_max_degree)
    }
}

impl ServerKey {
    /// Generates a server key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the server key:
    /// let sks = ServerKey::new_radix_server_key(&cks);
    /// ```
    pub fn new_radix_server_key<C>(cks: C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        // It should remain just enough space to add a carry
        let client_key = cks.as_ref();
        let max_degree = MaxDegree::integer_radix_server_key(
            client_key.key.parameters.message_modulus(),
            client_key.key.parameters.carry_modulus(),
        );

        let sks = crate::shortint::server_key::ServerKey::new_with_max_degree(
            &client_key.key,
            max_degree,
        );

        Self { key: sks }
    }

    pub fn new_crt_server_key<C>(cks: C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        let client_key = cks.as_ref();
        let max_degree = MaxDegree::integer_crt_server_key(
            client_key.key.parameters.message_modulus(),
            client_key.key.parameters.carry_modulus(),
        );

        let sks = crate::shortint::server_key::ServerKey::new_with_max_degree(
            &client_key.key,
            max_degree,
        );

        Self { key: sks }
    }

    /// Creates a ServerKey destined to be used with
    /// [`RadixCiphertext`](`crate::integer::RadixCiphertext`) from an already generated
    /// shortint::ServerKey.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ServerKey as ShortintServerKey;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the shortint server key:
    /// let shortint_sks = ShortintServerKey::new(cks.as_ref());
    ///
    /// // Generate the server key:
    /// let sks = ServerKey::new_radix_server_key_from_shortint(shortint_sks);
    /// ```
    pub fn new_radix_server_key_from_shortint(
        mut key: crate::shortint::server_key::ServerKey,
    ) -> Self {
        // It should remain just enough space add a carry
        let max_degree =
            MaxDegree::integer_radix_server_key(key.message_modulus, key.carry_modulus);

        key.max_degree = max_degree;
        Self { key }
    }

    /// Creates a ServerKey destined to be used with
    /// [`CrtCiphertext`](`crate::integer::CrtCiphertext`) from an already generated
    /// shortint::ServerKey.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ServerKey as ShortintServerKey;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the shortint server key:
    /// let shortint_sks = ShortintServerKey::new(cks.as_ref());
    ///
    /// // Generate the server key:
    /// let sks = ServerKey::new_crt_server_key_from_shortint(shortint_sks);
    /// ```
    pub fn new_crt_server_key_from_shortint(
        mut key: crate::shortint::server_key::ServerKey,
    ) -> Self {
        key.max_degree = MaxDegree::integer_crt_server_key(key.message_modulus, key.carry_modulus);
        Self { key }
    }

    pub fn deterministic_pbs_execution(&self) -> bool {
        self.key.deterministic_pbs_execution()
    }

    pub fn set_deterministic_pbs_execution(&mut self, new_deterministic_execution: bool) {
        self.key
            .set_deterministic_pbs_execution(new_deterministic_execution);
    }
    pub fn message_modulus(&self) -> MessageModulus {
        self.key.message_modulus
    }

    pub fn carry_modulus(&self) -> CarryModulus {
        self.key.carry_modulus
    }
}

impl AsRef<crate::shortint::ServerKey> for ServerKey {
    fn as_ref(&self) -> &crate::shortint::ServerKey {
        &self.key
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedServerKey {
    pub(crate) key: crate::shortint::CompressedServerKey,
}

impl CompressedServerKey {
    pub fn new_radix_compressed_server_key(client_key: &ClientKey) -> Self {
        let max_degree = MaxDegree::integer_radix_server_key(
            client_key.key.parameters.message_modulus(),
            client_key.key.parameters.carry_modulus(),
        );

        let key =
            crate::shortint::CompressedServerKey::new_with_max_degree(&client_key.key, max_degree);
        Self { key }
    }

    pub fn new_crt_compressed_server_key(client_key: &ClientKey) -> Self {
        let key = crate::shortint::CompressedServerKey::new(&client_key.key);
        Self { key }
    }
}

impl From<CompressedServerKey> for ServerKey {
    fn from(compressed: CompressedServerKey) -> Self {
        let key = compressed.key.into();
        Self { key }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::integer::RadixClientKey;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

    /// https://github.com/zama-ai/tfhe-rs/issues/460
    /// Problem with CompressedServerKey degree being set to shortint MaxDegree not accounting for
    /// the necessary carry bits for e.g. Radix carry propagation.
    #[test]
    fn test_compressed_server_key_max_degree() {
        {
            let cks = ClientKey::new(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS);
            // msg_mod = 4, carry_mod = 4, (msg_mod * carry_mod - 1) - (carry_mod - 1) = 12
            let expected_radix_max_degree = MaxDegree::new(12);

            let sks = ServerKey::new_radix_server_key(&cks);
            assert_eq!(sks.key.max_degree, expected_radix_max_degree);

            let csks = CompressedServerKey::new_radix_compressed_server_key(&cks);
            assert_eq!(csks.key.max_degree, expected_radix_max_degree);

            let decompressed_sks: ServerKey = csks.into();
            assert_eq!(decompressed_sks.key.max_degree, expected_radix_max_degree);
        }

        {
            let cks = ClientKey::new(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS);
            // msg_mod = 4, carry_mod = 4, msg_mod * carrymod - 1 = 15
            let expected_crt_max_degree = MaxDegree::new(15);

            let sks = ServerKey::new_crt_server_key(&cks);
            assert_eq!(sks.key.max_degree, expected_crt_max_degree);

            let csks = CompressedServerKey::new_crt_compressed_server_key(&cks);
            assert_eq!(csks.key.max_degree, expected_crt_max_degree);

            let decompressed_sks: ServerKey = csks.into();
            assert_eq!(decompressed_sks.key.max_degree, expected_crt_max_degree);
        }

        // Repro case from the user
        {
            let client_key = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2, 14);
            let compressed_eval_key =
                CompressedServerKey::new_radix_compressed_server_key(client_key.as_ref());
            let evaluation_key = ServerKey::from(compressed_eval_key);
            let modulus = (client_key.parameters().message_modulus().0 as u128)
                .pow(client_key.num_blocks() as u32);

            let mut ct = client_key.encrypt(modulus - 1);
            let mut res_ct = ct.clone();
            for _ in 0..5 {
                res_ct = evaluation_key.smart_add_parallelized(&mut res_ct, &mut ct);
            }
            let res: u128 = client_key.decrypt(&res_ct);
            assert_eq!(modulus - 6, res);
        }
    }
}
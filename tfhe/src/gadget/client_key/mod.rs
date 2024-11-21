//! The secret key of the client.
//!
//! This module implements the generation of the client' secret keys, together with the
//! encryption and decryption methods.

use crate::core_crypto::prelude::ContiguousEntityContainer;
use crate::gadget::prelude::*;
use crate::gadget::engine::{GadgetEngine, WithThreadLocalEngine};
use crate::gadget::parameters::GadgetParameters;
use crate::core_crypto::entities::*;
use std::fmt::{Debug, Formatter};

use super::ciphertext::Encoding;

use serde::{Serialize, Deserialize};
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use rmp_serde::encode;

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Clone)]
pub struct ClientKey {
    pub(crate) lwe_secret_key: LweSecretKeyOwned<u64>,
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u64>,
    pub(crate) parameters: GadgetParameters,
}

impl PartialEq for ClientKey {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters
            && self.lwe_secret_key == other.lwe_secret_key
            && self.glwe_secret_key == other.glwe_secret_key
    }
}

impl Debug for ClientKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientKey {{ ")?;
        write!(f, "lwe_secret_key: {:?}, ", self.lwe_secret_key)?;
        write!(f, "glwe_secret_key: {:?}, ", self.glwe_secret_key)?;
        write!(f, "parameters: {:?}, ", self.parameters)?;
        write!(f, "engine: CoreEngine, ")?;
        write!(f, "}}")?;
        Ok(())
    }
}

impl ClientKey {
    /// Encrypt a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() {
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, mut sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// # }
    /// ```
    // pub fn encrypt_boolean(&self, message: bool, encoding : &BooleanEncoding) -> Ciphertext {
    //     assert!(encoding.is_canonical());
    //     GadgetEngine::with_thread_local_mut(|engine| engine.encrypt_boolean(message, encoding, self))
    // }



    pub fn encrypt_arithmetic(&self, message: u64, encoding : &Encoding) -> Ciphertext {
        assert!(encoding.is_canonical());
        GadgetEngine::with_thread_local_mut(|engine| engine.encrypt_arithmetic(message, encoding, self))
    }

    

    /// Decrypt a ciphertext encrypting a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() {
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, mut sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// # }
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> u64 {
        GadgetEngine::with_thread_local_mut(|engine| engine.decrypt(ct, self))
    }


    ////////debug////////
    pub fn measure_noise(&self, ct: &Ciphertext) -> i64{
        GadgetEngine::with_thread_local_mut(|engine| engine.measure_noise(ct, self))
    }


    pub fn test_mvb(&self, ct : &GlweCiphertext<Vec<u64>>){
        GadgetEngine::with_thread_local_mut(|engine| engine.test_mvb(ct, self))
    }
    //////////////////////

    /// Allocate and generate a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() {
    /// use tfhe::boolean::client_key::ClientKey;
    /// use tfhe::boolean::parameters::TFHE_LIB_PARAMETERS;
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(&TFHE_LIB_PARAMETERS);
    /// # }
    /// ```
    pub fn new(parameter_set: &GadgetParameters) -> ClientKey {
        GadgetEngine::with_thread_local_mut(|engine| engine.create_client_key(*parameter_set))
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct SerializableKey{
    values: Vec<Vec<u64>>
}


impl SerializableKey{
    pub fn append_to_file(&self, filename: &str) -> io::Result<()> {
        let file = OpenOptions::new().append(true).create(true).open(filename)?;        
        let mut writer = BufWriter::new(file);
        encode::write(&mut writer, &self).unwrap();
        writer.flush()?;
        Ok(())
    }

    pub fn from_key(ck : &ClientKey, encryption_key_choice: EncryptionKeyChoice) -> Self{
        match encryption_key_choice {
            EncryptionKeyChoice::Big => {
                SerializableKey{
                    values: ck.clone().glwe_secret_key.as_lwe_secret_key().into_container().iter().map(|x| vec![*x]).collect()
                }
            }
            EncryptionKeyChoice::Small => {
                SerializableKey{
                    values: ck.clone().lwe_secret_key.into_container().iter().map(|x| vec![*x]).collect()
                }
            }
        }
    }

    pub fn glwe_big_key(ck: &ClientKey) -> Self{
        let values = ck.clone().glwe_secret_key.as_polynomial_list().iter().map(|poly| poly.iter().map(|x| *x).collect::<Vec<u64>>()).collect();
        Self {values}
    }

}

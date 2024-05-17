//! The public key for homomorphic computation.
//!
//! This module implements the generation of the server's public key, together with all the
//! available homomorphic Boolean gates ($\mathrm{AND}$, $\mathrm{MUX}$, $\mathrm{NAND}$,
//! $\mathrm{NOR}$,
//! $\mathrm{NOT}$, $\mathrm{OR}$, $\mathrm{XNOR}$, $\mathrm{XOR}$).

#[cfg(test)]
mod tests;


use itertools::Itertools;

use crate::gadget::prelude::*;
use crate::gadget::client_key::ClientKey;
pub use crate::gadget::engine::bootstrapping::ServerKey;
use crate::gadget::engine::{
    BooleanEngine, WithThreadLocalEngine,
};


impl ServerKey {
    ////Boolean only : gadget logic (see paper)//////
    pub fn exec_gadget_with_extraction(&self, enc_in : &Vec<Encoding>, enc_inter : &Encoding, enc_out : &Encoding, input : &Vec<Ciphertext>) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.exec_gadget_with_extraction(enc_in, enc_inter, enc_out, input, &self))
    }
    //////////////////////////////////////////////////
    


    ///Arithmetic only : application of LUT from Zo to Zo
    pub fn apply_lut(&self, input : &Ciphertext, encoding_out : &Encoding, f : &dyn Fn(u32) -> u32) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.apply_lut(input, encoding_out, f, self))
    }
    ///////////////////////////////////////////////////
    

    pub fn mvb(&self, input : &Ciphertext, encodings_out : &Vec<Encoding>, fis : &Vec<Box<dyn Fn(u32) -> u32>>) -> Vec<Ciphertext>{
        assert_eq!(encodings_out.len(), fis.len());

        match input{
            Ciphertext::EncodingEncrypted(_, encoding) => {
                let lut_fis : Vec<Vec<u32>> = fis.iter()
                                                                        .map(|fi| (0..encoding.get_origin_modulus()).map(fi).collect())
                                                                        .collect();

                BooleanEngine::with_thread_local_mut(|engine| engine.mvb(input, encodings_out, &lut_fis, self))
            }
            _ => panic!("No mvb with trivial ciphertexts")
        }
    }

    pub fn full_tree_bootstrapping(
        &self,
        inputs: &Vec<Ciphertext>,
        encodings_out: &Vec<Encoding>,
        t: u32,
        f: &dyn Fn(u32) -> u32,
        client_key_debug: &ClientKey,
        log : bool
    ) -> Vec<Ciphertext> {
        let origin_submodulis: Vec<u32> = inputs
            .iter()
            .map(|c| match c {
                Ciphertext::EncodingEncrypted(_, encoding) => encoding.get_origin_modulus(),
                Ciphertext::Trivial(_) => panic!("No tree bootstrapping with trivial ciphertexts (yet)"),
            })
            .collect();
    
        assert_eq!(origin_submodulis.iter().product::<u32>(), t);
    
        let o = origin_submodulis[0];
        let lut_f0 = (0..t).map(|x| f(x) % o).collect_vec();
        let lut_f1 = (0..t).map(|x: u32| (f(x) - f(x) % o) / o).collect_vec();
    
        let r0 = BooleanEngine::with_thread_local_mut(|engine| {
            engine.simple_tree_bootstrapping(inputs, &encodings_out[0], t, lut_f0, &self, client_key_debug, log)
        });
    
        let r1 = BooleanEngine::with_thread_local_mut(|engine| {
            engine.simple_tree_bootstrapping(inputs, &encodings_out[1], t, lut_f1, &self, client_key_debug, false)
        });
    
        vec![r1, r0]
    }
    
     
    
    ///Encoding Switching : universal
    pub fn encoding_switching_lut(&self, input : &Ciphertext, encoding_out : &Encoding) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.apply_lut(input, encoding_out, &|x|{x}, self))
    }

    //transforme un encodage en un autre avec un external product par un coefficient donné
    pub fn encoding_switching_mul_constant(&self, input : &Ciphertext, coefficient : u32) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.encoding_switching_mul_constant(input, coefficient, &self))
    }

    pub fn encoding_switching_sum_constant(&self, input : &Ciphertext, constant : u32, modulus : u32) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.encoding_switching_sum_constant(input, constant, modulus,&self))
    }
    ////////////////////////


    ///Simple Sum : (only boolean for now)
    //simple sum : no check is performed so use it wisely
    pub fn simple_sum(&self, input : &Vec<Ciphertext>) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.simple_sum(input, &self))
    }

    pub fn simple_plaintext_sum(&self, input : &Ciphertext, constant : u32, modulus : u32) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.simple_plaintext_sum(input, constant, modulus,&self))
    }


}


impl ServerKey {
    pub fn new(cks: &ClientKey) -> Self {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_server_key(cks))
    }

    pub fn trivial_encrypt(&self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }
}


use std::collections::HashSet;

use super::{prelude::*, ciphertext::Encoding};


pub struct Gadget{
    encodings_in : Vec<Encoding>,
    encoding_inter : Encoding,
    encoding_out : Encoding,
    size_input : u64,
    true_result : Vec<u64> //index of an element encodes the input
}




// impl Gadget{

//     pub fn pretty_print(&self){
//         self.encodings_in.iter().for_each(|e| print!("{}|", e.get_part_single_value_if_canonical(1)));
//         println!(" -> {}", self.encoding_out.get_part_single_value_if_canonical(1));
//     }

//     pub fn get_encoding_in(&self, index : usize) -> &Encoding{
//         &self.encodings_in[index]
//     }

//     pub fn get_encoding_out(&self) -> &Encoding{
//         &self.encoding_out
//     }


//     pub fn get_modulus_in(&self) -> u64{
//         self.get_encoding_in(0).get_modulus()
//     }


//     pub fn get_modulus_out(&self) -> u64{
//         self.get_encoding_out().get_modulus()
//     }



//     pub fn new(encodings_in : Vec<Encoding>, encoding_inter : Encoding, encoding_out : Encoding, size_input : u64, true_fn : &dyn Fn(Vec<u64>) -> u64) -> Self{
//         for e in &encodings_in{
//             assert!(e.is_canonical());
//         }
//         assert!(encoding_out.is_canonical());
//         let true_result : Vec<u64> = (0..1<<size_input).map(|x| true_fn(Self::split_int_in_booleans(x, size_input.try_into().unwrap(), false))).collect();
//         Self{
//             encodings_in, encoding_inter, encoding_out, size_input, true_result
//         }
//     }


//     pub fn new_canonical(qis : Vec<u64>,  q_out : u64, p_in : u64, p_out : u64,  size_input : u64, true_fn : &dyn Fn(Vec<u64>) -> u64) -> Self{
//         let encodings_in : Vec<Encoding> = qis.iter().map(|x| Encoding::new_canonical_binary(*x, p_in)).collect();
//         Self::new(encodings_in, Self::compute_sum_encodings_from_canonical_binary(&qis, p_in, size_input, true_fn), Encoding::new_canonical_binary(q_out, p_out), size_input, true_fn)
//     }


//     fn compute_sum_encodings_from_canonical_binary(qis : &Vec<u64>, p : u64, size_input : u64, true_fn : &dyn Fn(Vec<u64>) -> u64) -> Encoding{
//         let mut part_false : HashSet<u64> = HashSet::new();
//         let mut part_true : HashSet<u64> = HashSet::new();
//         for i in 0..1<<size_input{
//             let input = Self::split_int_in_booleans(i, size_input as usize, true);
//             let result : u64 = input.iter().zip(qis).map(|(b, q)| if *b == 1 {*q} else {0}).sum::<u64>() % p;
//             if true_fn(input) == 1{
//                 assert!(! part_false.contains(&result));
//                 part_true.insert(result);
//             }
//             else{
//                 assert!(! part_true.contains(&result));
//                 part_false.insert(result);
//             }
//         }
//         Encoding::new(2, vec![part_false, part_true], p)
//     }



//     pub fn split_int_in_booleans(x : u64, expected_length : usize, big_endian : bool) -> Vec<u64>{
//         //util function
//         let mut res = Vec::new();
//         let mut y = x;
//         while y != 0{
//             res.push(y % 2 == 1);
//             y = y >> 1;
//         }
//         (0..expected_length - res.len()).for_each(|_i| res.push(false));
//         let mut res_integer : Vec<u64> = res.iter().map(|x| if *x {1} else {0}).collect();
//         if big_endian{  res_integer.reverse(); }
//         res_integer
//     }


//     pub fn vec_bool_to_int(x : Vec<u64>, big_endian : bool) -> u64{
//         let mut index = 0;
//         let mut x_copy = x.clone();
//         if big_endian{
//             x_copy.reverse();
//         }
//         x_copy.iter()
//         .enumerate()
//         .for_each(|(i, x)| if *x == 1 {index = index + (1 << i)});
//         index
//     }


//     pub fn test_full(&self, client_key : &ClientKey, server_key : &ServerKey){
//         for x in 0..1 << self.size_input{
//             println!("{}", x);
//             let c_clear = Self::split_int_in_booleans(x, self.size_input as usize, false);
//             c_clear.iter().for_each(|x| print!("| {} ", *x));
//             println!(" -> {}", self.true_result[x as usize]);
//             let c: Vec<Ciphertext> = c_clear.iter().enumerate().map(
//                 |(i, x_i)| client_key.encrypt_arithmetic(*x_i, &self.encodings_in[i])
//             ).collect();
//             let res: Ciphertext = self.exec(&c, &server_key);
//             if client_key.decrypt(&res) == self.true_result[x as usize]{  
//                 println!("valid");
//             }
//             else{
//                 println!("failed with float {}", client_key.measure_noise(&res));
//             }
//             assert_eq!(client_key.decrypt(&res), self.true_result[Self::vec_bool_to_int(c_clear, false) as usize]);
//         }
//         println!("TEST OK !");
//     }

    


//     pub fn exec_clear(&self, input : Vec<u64>) -> u64{
//         self.true_result[Self::vec_bool_to_int(input, false) as usize]
//     }

    
//     pub fn exec(&self, input : &Vec<Ciphertext>, server_key : &ServerKey) -> Ciphertext{
//         input.iter().zip(self.encodings_in.clone()).for_each(|(e_1, e_2)| {
//             match e_1{
//                 Ciphertext::EncodingEncrypted(_, enc_1) => assert_eq!(*enc_1, e_2),
//                 Ciphertext::Trivial(_) => {}
//             }
//         });
//         server_key.exec_gadget_with_extraction(&self.encodings_in, &self.encoding_inter, &self.encoding_out, &input)
//     }


//     pub fn cast_before_gadget(&self, coefficients : Vec<u64>, inputs : &Vec<Ciphertext>, server_key : &ServerKey) -> Vec<Ciphertext>{
//         // input encodees sous {0}, {1}
//         let mut result : Vec<Ciphertext> = Vec::new();
//         inputs.iter().zip(coefficients).for_each(|(x, c)| if c != 0 {result.push(server_key.encoding_switching_mul_constant(x, c))});
//         result
//     }


//     pub fn cast_before_gadget_from_1(&self, inputs : Vec<Ciphertext>, server_key : &ServerKey) -> Vec<Ciphertext>{
//         let coefficients : Vec<u64>= self.encodings_in.iter().map(|e| e.get_part_single_value_if_canonical(1)).collect();
//         self.cast_before_gadget(coefficients, &inputs, server_key)
//     }


//     pub fn modulus_switching(&self, inputs : Vec<Ciphertext>, p_in_vec : Vec<u64>, p_out : u64, server_key : &ServerKey) -> Vec<Ciphertext> {
//         assert_eq!(inputs.len(), p_in_vec.len());
//         inputs.iter().zip(p_in_vec).map(|(x, p_i)| {
//             if p_i != p_out {
//                 let gadget = Gadget::new_canonical(vec![1], 1, p_i, p_out, 1, &|x| {x[0]});
//                 gadget.exec(&vec![x.clone()], &server_key)
//             } else {
//             x.clone()
//             }
//         }).collect()
//     }

// }

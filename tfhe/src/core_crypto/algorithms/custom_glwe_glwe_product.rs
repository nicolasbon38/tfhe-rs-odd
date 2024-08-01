use std::cmp::max;

use pulp::Scalar;

use crate::core_crypto::commons::math::decomposition::SignedDecompositionIter;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::polynomial_algorithms::{polynomial_karatsuba_wrapping_mul, polynomial_wrapping_add_assign, polynomial_wrapping_add_mul_assign, polynomial_wrapping_mul};
use crate::core_crypto::prelude::slice_algorithms::slice_wrapping_add_assign;
use crate::core_crypto::prelude::SignedDecomposer;



pub fn glwe_ciphertext_mult<Scalar, OutputCont, LhsCont, RhsCont, KeyCont>(
    output: &mut GlweCiphertext<OutputCont>,
    lhs: &GlweCiphertext<LhsCont>,
    rhs: &GlweCiphertext<RhsCont>,
    rlk : &RelinearizationKey<KeyCont>
) where
    Scalar : UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
    KeyCont : Container<Element = Scalar>
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) GlweCiphertext",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        lhs.polynomial_size(),
        rhs.polynomial_size(),
        "Mismatched polynomial size between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.polynomial_size(),
        rhs.polynomial_size()
    );

    assert_eq!(
        output.polynomial_size(),
        rhs.polynomial_size(),
        "Mismatched polynomial_size between output ({:?}) and rhs ({:?}) GlweCiphertext",
        output.polynomial_size(),
        rhs.polynomial_size()
    );

    assert_eq!(
        output.glwe_size(),
        rhs.glwe_size(),
        "Mismatched glwe_size between output ({:?}) and rhs ({:?}) GlweCiphertext",
        output.glwe_size(),
        rhs.glwe_size()
    );

        assert_eq!(
        lhs.glwe_size(),
        rhs.glwe_size(),
        "Mismatched glwe_size between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.glwe_size(),
        rhs.glwe_size()
    );

    let polynomial_size = output.polynomial_size();
    let ciphertext_modulus = output.ciphertext_modulus();
    let glwe_size = output.glwe_size();

    /* Tensor product */

    let t : Vec<_> = lhs.get_mask()
                        .as_polynomial_list()
                        .iter()
                        .zip(rhs.as_polynomial_list().iter())
                        .map(|(lhs_poly, rhs_poly)|{
                            let mut ka_mul = Polynomial::new(Scalar::ZERO, polynomial_size);    
                            polynomial_karatsuba_wrapping_mul(&mut ka_mul, &lhs_poly, &rhs_poly);
                            ka_mul
                        }).collect();

    let k = lhs.glwe_size().0 - 1;    //vérifier le -1

    let r_prime : Vec<Vec<_>> = (0..k)
                                .map(|i|{
                                    (0..i)
                                    .map(|j| {
                                        let mut buf1 = Polynomial::new(Scalar::ZERO, polynomial_size);    
                                        polynomial_karatsuba_wrapping_mul(
                                            &mut buf1,
                                            &lhs.as_polynomial_list().get(i), 
                                            &rhs.as_polynomial_list().get(j)
                                        );
                                        let mut buf2 = Polynomial::new(Scalar::ZERO, polynomial_size);    
                                        polynomial_karatsuba_wrapping_mul(
                                            &mut buf2,
                                            &lhs.as_polynomial_list().get(j), 
                                            &rhs.as_polynomial_list().get(i)
                                        );
                                        polynomial_wrapping_add_assign(&mut buf1, &buf2);                          
                                        buf1
                                    })
                                    .collect()                                       
                                }).collect();

    let a_prime : Vec<_> = lhs.get_mask()
                        .as_polynomial_list()
                        .iter()
                        .zip(rhs.get_mask().as_polynomial_list().iter())
                        .map(|(lhs_poly, rhs_poly)|{
                            let mut buf1 = Polynomial::new(Scalar::ZERO, polynomial_size);    
                            polynomial_karatsuba_wrapping_mul(
                                &mut buf1,
                                &lhs_poly, 
                                &rhs.get_body().as_polynomial()
                            );
                            let mut buf2 = Polynomial::new(Scalar::ZERO, polynomial_size);    
                            polynomial_karatsuba_wrapping_mul(
                                &mut buf2,
                                &rhs_poly,
                                &lhs.get_body().as_polynomial()
                            );
                            polynomial_wrapping_add_assign(&mut buf1, &buf2);                          
                            buf1
                        }).collect();

    let mut b_prime = Polynomial::new(Scalar::ZERO, polynomial_size);
    polynomial_karatsuba_wrapping_mul(
        &mut b_prime,
        &lhs.get_body().as_polynomial(), 
        &rhs.get_body().as_polynomial()
    );
    
    //Relinearization


    output.get_mut_mask().as_mut_polynomial_list().iter_mut().zip(a_prime.iter()).for_each(|(mut lhs, rhs)|{
        polynomial_wrapping_add_assign(&mut lhs, &rhs);
    });
    polynomial_wrapping_add_assign(&mut output.get_mut_body().as_mut_polynomial(), &b_prime);

    //first sum
    //instantiate the decomposer
    let decomposer = SignedDecomposer::new(
        rlk.decomposition_base_log(),
        rlk.decomposition_level_count(),
    );

    let triangular_numbers: Vec<usize> = (0..=glwe_size.0 - 1).map(|i| i * (i+1) / 2).collect();
    rlk.iter().enumerate().for_each(|(n, rlk_block)|{
            // to find i and j, we use the fact that i is the "root" of the greater triangular number smaller equal of n
            let mut i = 0;
            while triangular_numbers[i] <= n{
                i = i + 1;
            }
            i = max(1, i);
            i = i-1;
            let j = n - triangular_numbers[i];    
    
            
            let mut decomposition = if i == j{
                decomposer.decompose_polynomial(t[i].clone())
            }else{
                    decomposer.decompose_polynomial(r_prime[i][j].clone())
            };
            
            for rlk_block_ciphertext in rlk_block.iter(){
                //on reconstruit le index-ieme polynome décomposé
                let decomposed_values : Vec<Scalar> = decomposition.iter_mut().map(|mut coeff_decomposition_iter| coeff_decomposition_iter.next().unwrap().value()).collect();
                let decomposed_polynomial_item = Polynomial::from_container(decomposed_values);

                output.as_mut_polynomial_list().iter_mut().zip(rlk_block_ciphertext.as_polynomial_list().iter()).for_each(|(mut output_poly, rlk_poly)|{
                    let mut buffer = Polynomial::new(Scalar::ZERO, polynomial_size);
                    polynomial_karatsuba_wrapping_mul(&mut buffer, &rlk_poly, &decomposed_polynomial_item);
                    polynomial_wrapping_add_assign(&mut output_poly, &buffer);
                })                    
            }
    })


}
import tenseal.sealapi as seal
from math import ceil, log2
import util 

# Given an array of coefficients [c_0, c_1, ..., c_n], an array of degrees [p_0, p_1, ..., p_n],
# an encrypted argument x and a power of 2, pow
#  this function calculates the (encrypted) value of the polynomial 
# f(x) = c_0*x^p_0 + ... + c_n*x^p_n
def enc_poly(arg: seal.Ciphertext, coefficients, degrees, power: int, evaluator: seal.Evaluator, context:seal.SEALContext, encoder:seal.CKKSEncoder, parms:seal.EncryptionParameters, relin_keys:seal.RelinKeys, encryptor:seal.Encryptor):
    
    # What are the specific primes in the modulus chain? 
    primes = [modulus.value() for modulus in parms.coeff_modulus()]

    # What is the maximum depth circuit we can evaluate? 
    # First and last primes are "special" and do not represent
    # data levels, therefore subtract 2. 
    max_depth = len(primes)-2

    # Assumes degrees is sorted, with highest number at the end.
    # Check that there are enough available CT-levels. 
    if ceil(log2(degrees[-1])) > max_depth:
        raise ValueError(f"ValueError: not enough ciphertext levels for degree {degrees[-1]} polynomial.")
    
    #------------------- Step 1 ----------------------# 
    # Calculate all different degrees and save in arg_degrees
    arg_degrees = []
    
    # Need to know the scale of the argument
    original_scale = arg.scale

    # We need an encryption of 1 to initialize the square and multiply algorithm, 
    # which needs to have the correct parameters and scale.
    plain_init = seal.Plaintext()
    encoder.encode(1,original_scale, plain_init)
    for exponent in degrees:
        # Allocate variable to store x^exponent, initialize to be 
        # an encryption of 1.
        x_deg = seal.Ciphertext()
        encryptor.encrypt(plain_init, x_deg)

        # We need to operate on a fresh copy of the encrypted argument
        arg_copy = bad_copy(arg, original_scale, evaluator, encoder)

        # Note that we need to waste at least one CT-level when 
        # using this copy method. 
        evaluator.mod_switch_to_inplace(x_deg, arg_copy.parms_id())

        square_and_multiply(arg_copy, exponent, evaluator, relin_keys, original_scale, encoder, x_deg)
        arg_degrees.append(x_deg)

    #-------------------- STEP 2 -----------------------#
    # We can now "multiply" by the PT coefficient, this is done by 
    # by repeatedly adding CT to avoid multiplications. 
    # (inspired by sorting article using CKKS)
    index = 0
    for coeff in coefficients:
        tmp_result = seal.Ciphertext()
        add_many_coeff(abs(coeff), arg_degrees[index], evaluator, tmp_result)
        divByPo2(tmp_result, power)
        arg_degrees[index] = tmp_result
        index+=1
    
    #-------------------- STEP 3 -----------------------#
    # Now, we need to check such that all CT are at the same level. 
    # Furthermore, we must make sure that they all have the same scale, 
    # this is done by manually forcing it to be the same, following
    # `5_ckks_basics.ipynb`. Note that this leads to precision loss, 
    # but is the simplest method. 
    # We also need to take the sign of the coefficient into account

    # The highest degree term will be at the lowest level, meaning
    # all other CT must be switched to this level. 
    min_level = context.get_context_data(arg_degrees[-1].parms_id()).chain_index()
    index = 0
    for ct in arg_degrees:
        if coefficients[index]<0:
            evaluator.negate_inplace(arg_degrees[index])
        if context.get_context_data(ct.parms_id()).chain_index() > min_level:
            evaluator.mod_switch_to_inplace(ct, arg_degrees[-1].parms_id())
        ct.scale = arg_degrees[-1].scale
        index+=1
    
    #-------------------- STEP 4 -----------------------#
    # Add result together into the destination CT result
    result = seal.Ciphertext()
    evaluator.add_many(arg_degrees, result)

    return result


# Worst way of copying a ciphertext - multiply by plaintext 1. Consumes one ciphertext level. 
def bad_copy(cipher : seal.Ciphertext,scale : float, evaluator  : seal.Evaluator, encoder : seal.CKKSEncoder):
    dummy_plain = seal.Plaintext()
    encoder.encode(1, scale, dummy_plain)
    if dummy_plain.parms_id() != cipher.parms_id():
        evaluator.mod_switch_to_inplace(dummy_plain, cipher.parms_id())
    copy = seal.Ciphertext()
    evaluator.multiply_plain(cipher, dummy_plain, copy)

    evaluator.rescale_to_next_inplace(copy)
    
    return copy 

# A function for controlling size and scale of ciphertext after multiplication
def relinearize_and_rescale_inplace(cipher : seal.Ciphertext, evaluator : seal.Evaluator, relin_keys : seal.RelinKeys):
    # Control size by relinearization
    evaluator.relinearize_inplace(cipher, relin_keys)
    # Control scale by rescaling
    evaluator.rescale_to_next_inplace(cipher)

    # evaluator::exponentiate not supported for CKKS, 
    # write separate function for exponentiation, note that "res" 
    # should be an encryption of 1 for this to work. 
def square_and_multiply(cipher : seal.Ciphertext, exp : int,  evaluator : seal.Evaluator, relin_keys : seal.RelinKeys,scale : int, encoder: seal.CKKSEncoder, res : seal.Ciphertext): 

    if exp==0:
        raise ValueError("Exponent cannot be zero --> transparent ciphertext.")
    binary_exp = bin(exp)[2:]
    for char in binary_exp[::-1]:
        if char=='1':
            if res.data() == None:
                raise ValueError("Ciphertext res must be initialized to 1.")
            else:
                evaluator.multiply_inplace(res, cipher)
                relinearize_and_rescale_inplace(res, evaluator, relin_keys)
                evaluator.square_inplace(cipher)
                relinearize_and_rescale_inplace(cipher, evaluator, relin_keys)
        else:
            evaluator.square_inplace(cipher)
            relinearize_and_rescale_inplace(cipher,evaluator, relin_keys)
            evaluator.mod_switch_to_next_inplace(res)

# Divide by power of 2, divides cipher by 2**power
def divByPo2(cipher: seal.Ciphertext, power : int):
    cipher.scale = cipher.scale*(2**power)

# Multiply by PT coefficient by repeated addition. 
def add_many_coeff(coeff: int, cipher: seal.Ciphertext,evaluator: seal.Evaluator, result: seal.Ciphertext):
    tmp = []
    for i in range(coeff):
        tmp.append(cipher)
    evaluator.add_many(tmp, result)
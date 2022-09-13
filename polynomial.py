import tenseal.sealapi as seal
import util

# Given an array of coefficients [c_0, c_1, ..., c_n], an array of degrees [p_0, p_1, ..., p_n],
# an encrypted argument x and a power of 2, pow
#  this function calculates the (encrypted) value of the polynomial 
# f(x) = c_0*x^p_0 + ... + c_n*x^p_n
def enc_poly(arg: seal.Ciphertext, coefficients, degress, power: int, evaluator: seal.Evaluator, context:seal.SEALContext):
    
    
    return 0


# Worst way of copying a ciphertext - multiply by plaintext 1. Consumes one ciphertext level. 
def bad_copy(cipher : seal.Ciphertext,scale : int, evaluator  : seal.Evaluator, encoder : seal.CKKSEncoder):
    dummy_plain = seal.Plaintext()
    encoder.encode(1, scale, dummy_plain)

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

    # evaluator::exponentiate not supported for CKKS, write separate function for exponentiation, note that "res" 
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
                #print("Current scale:\t" + str(res.scale))
                evaluator.multiply_inplace(res, cipher)
                relinearize_and_rescale_inplace(res, evaluator, relin_keys)
                evaluator.square_inplace(cipher)
                relinearize_and_rescale_inplace(cipher, evaluator, relin_keys)
                #print("Current scale:\t" + str(res.scale))
        else:
            evaluator.square_inplace(cipher)
            relinearize_and_rescale_inplace(cipher,evaluator, relin_keys)
            evaluator.mod_switch_to_next_inplace(res)

# Divide by power of 2, divides cipher by 2**power
def divByPo2(cipher: seal.Ciphertext, power : int):
    cipher.scale = cipher.scale*(2**power)
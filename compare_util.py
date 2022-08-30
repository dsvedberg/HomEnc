import tenseal.sealapi as seal


# divByPo2(Ciphertext cipher, int exponent): since right/left shifting is not supported in SEAL, I will instead manually change 
# the scale of the ciphertext, which does not introduce error.
def divByPo2(cipher: seal.Ciphertext, power: int):
    tmp = cipher.scale
    cipher.scale = tmp/2**power


# multiply_coeff(cipher, coeff): multiplies the ciphertext by the coefficient by repeated addition to decrease mult. depth
def multiply_coeff(cipher: seal.Ciphertext, coeff: int, evaluator: seal.Evaluator):
    res = cipher.copy()
    for i in range(coeff):
        evaluator.add_inplace(cipher, res)

def exponentiate(cipher: seal.Ciphertext, power: int, relin_keys: seal.RelinKeys,evaluator: seal.Evaluator, res: seal.Ciphertext):
    exponent=1
    while exponent<power:
        evaluator.square_inplace()
        exponent*=2


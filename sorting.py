from re import search
from tkinter.tix import MAX
import tenseal.sealapi as seal
import polynomial
from math import ceil, floor

def compare(x: seal.Ciphertext, y: seal.Ciphertext, evaluator: seal.Evaluator, context:seal.SEALContext, encoder:seal.CKKSEncoder, relin_keys:seal.RelinKeys, encryptor:seal.Encryptor, reset_scale:bool, *original_scale:int):
    arg = seal.Ciphertext()
    evaluator.sub(x, y, arg)

    original_scale = arg.scale
    
    degrees = [1, 3, 4, 5, 7]
    coeffs1 = [35, -35, 21, -5]
    power1 = 4

    coeffs2 = [4589, -16577, 25614, -12860]
    power2 = 10

    g_x = polynomial.enc_poly(arg, coeffs1, degrees, power1, evaluator, context, encoder, relin_keys, encryptor, True, original_scale)
    f_x = polynomial.enc_poly(g_x, coeffs2, degrees, power2, evaluator, context, encoder, relin_keys, encryptor, False)

    # Rescaled and shifted version of f(g(x))
    plain_one = seal.Plaintext()
    encoder.encode(1, f_x.scale, plain_one)
    evaluator.add_plain_inplace(f_x, plain_one)
    polynomial.divByPo2(f_x, 1)
    return f_x


# Define L from page 12 in "Efficient Sorting of Homomorphic Encrypted Data..." 
def L(a,b, F,G):
    a_larger_than_b = a>b
    b_larger_than_a = a<b

    return a_larger_than_b*F+b_larger_than_a*G

# Define m-th Max algorithm for 2 sorted arrays
def max(m, B, C, comparisons):
    if len(B)==0 or len(C)==0:
        if len(B)==0:
            return C[m]
        else:
            return B[m]
    else:
        i = floor(m/2)
        j =  ceil(m/3)
        left = max(j, B[i+1:], C[:j], comparisons[i+1:,:j])
        right = max(i, B[:i], C[j+1:], comparisons[:i,j+1:])
        return L(B[i],C[j],left, right)

def min(m, B, C, comparisons):
    s = len(B)
    t = len(C)
    if s==0 or t==0:
        if s==0:
            return C[m]
        else:
            return B[m]
    else:
        i = s-floor(m/2)
        j = t-floor(m/2)
        left = min(j, B[:i-1], C[j:],comparisons[:i-1,j:])
        right = min(i,B[i:],C[:j-1],comparisons[i:,:j-1])
        return L(C[j],B[i],left, right)

# Will start with a fixed-size array of size 4. Arguments in plaintext. 
def sorter(A, comparisons):
    k = len(A)
    if k == 1:
        return A
    
    s = floor(k/2)
    t = ceil(k/2)

    B = sorter(A[:s], comparisons[:s,:s])
    C = sorter(A[s+1:],comparisons[s+1:,s+1:])
    B_larger_than_a = []
    b_larger_than_C = []
    for j in range(s+1, k):
        B_larger_than_a.append(sorter(comparisons[:s,j], comparisons[:s,:s]))
    for i in range(s):
        b_larger_than_C.append(comparisons[i,])
        


def merge(B,C,comparisons):
    s = len(B)
    t = len(C)
    k = floor((s+t)/2)
    Z = []
    for i in range(k):
        Z.append(max(i, B, C, comparisons))
    
    for j in range(k+2, s+t):
        Z.append(min(s+t-j,B,C,comparisons))
    
    z_k = sum(B)+sum(C)-sum(Z)
    Z.insert(k, z_k)
    return Z

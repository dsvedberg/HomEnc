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

def compare_plain(x, y):
    return x > y

# Define L from page 12 in "Efficient Sorting of Homomorphic Encrypted Data..." 
def L(a_larger_than_b, F,G):
    # This will be replaced by approximate, encrypted comparison
    return a_larger_than_b*F+(1-a_larger_than_b)*G

# Define m-th Max algorithm for 2 sorted arrays
def max(m, B, C, comparisons):
    s = len(B)
    t =len(C)
    if s==0 or t==0:
        if s==0:
            return C[m-1]
        else:
            return B[m-1]
    else:
        i = floor(m/2)
        j =  ceil(m/2)
        if i==0:
            return L(comparisons[i][j-1], B[i],C[j-1])
        
        left = max(j, B[i:], C[:j], [comp[:j] for comp in comparisons[i:]])
        right = max(i, B[:i], C[j:], [comp[j:] for comp in comparisons[:i]])
        if len(comparisons) < i:
            return right
        elif len(comparisons[i-1]) < j:
            return left
        else:
            return L(comparisons[i-1][j-1],left, right)

def min(m, B, C, comparisons):
    s = len(B)
    t = len(C)
    return max(s+t-m+1,B,C,comparisons)


# Sorts an array of size k, using pairwise comparisons from in "comparisons"
def sorter(A, comparisons):
    k = len(A)
    if k == 1:
        return A
    
    s = floor(k/2)
    t = ceil(k/2)

    B = sorter(A[:s], [[el for el in comp[:s]] for comp in comparisons[:s]])
    C = sorter(A[s:], [[el for el in comp[s:]] for comp in comparisons[s:]])

    B_larger_than_C = []
 
    B_larger_than_a = sorter([comp[s:] for comp in comparisons[:s]], [[el for el in comp[:s]] for comp in comparisons[:s]])
    for i in range(s):
        B_larger_than_C.append(sorter(B_larger_than_a[i],[[el for el in comp[s:]] for comp in comparisons[s:]]))
    return merge(B,C,B_larger_than_C)

        
def merge(B,C,comparisons):
    s = len(B)
    t = len(C)
    k = s+t
    Z = []
    for i in range(k):
        Z.append(max(i+1, B, C, comparisons))
    return Z

if __name__ == "__main__":
#    B = [6,4,2]
#    C = [5,3,1] 
    A = [4,6,3,5,1,335,45,0,1245]
    comparisons = [[bel > cel for cel in A] for bel in A]
#     m = 3
#    print(f"{m}th smallest element")
#    print(max(len(B)+len(C)-m+1, B,C, comparisons))
#    print(f"{m}th largest element")
#    print(max(m,B,C,comparisons))  
    A = sorter(A, comparisons)
    print(A)

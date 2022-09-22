
import tenseal.sealapi as seal

def _to_hex_string(value, len = 8):
    """
    Convert an integer to a hex string.
    """

    num_nibbles = int(len/4)
    output = ''
    for i in range(num_nibbles-1, -1, -1):
        nibble = hex(value & 0x0F)[2]
        output = nibble + output
        value >>= 4

    return output

def uint_to_hex_string(values):
    # Start with a string with a zero for each nibble in the array.
    num_values = 1
    if hasattr(values, '__len__'):
        num_values = len(values)

    # Iterate through each uint64 in array and set string with correct nibbles in hex.
    # N.B.: Reverse order to comply with the order of the C++ implementation
    output = ''
    for i in range(num_values-1, -1, -1):
        if num_values > 1:
            value = values[i]
        else:
            value = values

        output = output + _to_hex_string(value, 64)

    # Strip leading zeros
    leftmost_non_zero_pos = len(output)
    for i in range(len(output)-1, -1, -1):
        if output[i] != '0':
            leftmost_non_zero_pos = i
            
    output = output[leftmost_non_zero_pos:]
    if output == '':
        output = '0'
    
    return output

def print_parameters(context):
    #prints the parameters in a SEALContext
    context_data = context.key_context_data()
    scheme_name = context_data.parms().scheme()
    if scheme_name==seal.SCHEME_TYPE.BFV:
        scheme_name = "BFV"
    elif scheme_name==seal.SCHEME_TYPE.CKKS:
        scheme_name = "CKKS"
    else:
        raise ValueError

    print("/")
    print("|Encryption parameters: ")
    print("|\tscheme: " + scheme_name)
    print("|\tpoly_modulus_degree: " + str(context_data.parms().poly_modulus_degree()))
    print("|\tcoeff_modulus_size: " + str(context_data.total_coeff_modulus_bit_count()) + " (", end='')
    coeff_modulus = context_data.parms().coeff_modulus()
    coeff_modulus_size = len(coeff_modulus)
    for i in range(coeff_modulus_size-1):
        print(str(coeff_modulus[i].bit_count()), end=' ')
    
    print(str(coeff_modulus[-1].bit_count()) + ") bits")
    
    if(scheme_name=="BFV"):
        print("|\tplain_modulus: " + str(context_data.parms().plain_modulus().value()))
    
    print(f"|\tMax Bit Count: {seal.CoeffModulus.MaxBitCount(context_data.parms().poly_modulus_degree(), seal.SEC_LEVEL_TYPE.TC128)}")

def largest_number_of_2(num : int):
    # Start with exponent exp equal to 0
    exp = 0
    # Store result of 2**exp in res. 
    res = 1
    # Iterate until NEXT res will be larger than num
    while 2*res < num:
        exp += 1
        res *= 2
    return exp

def print_info(cipher:seal.Ciphertext, decryptor:seal.Decryptor, context:seal.SEALContext, encoder:seal.CKKSEncoder, true_result:float):
    tmp_plain = seal.Plaintext()
    decryptor.decrypt(cipher, tmp_plain)
    print(f"\tEnc. result:\t{encoder.decode_double(tmp_plain)[0]}")
    print(f"\tPlain result:\t{true_result[0]}")
    print(f"\tScale:\t{cipher.scale}")
    print(f"\tCh. ind:\t{context.get_context_data(cipher.parms_id()).chain_index()}")
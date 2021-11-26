#!/usr/bin/env python3
#!/bin/env python3

import random
import argparse
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import inverse
from Crypto.Math._IntegerGMP import IntegerGMP
import hashlib
import sympy

# generate:
# - pk_H = (c,d,h,(G,)q,g1,g2)    (each `GP_ELT_BITSIZE`)
# - sk_H = (x1,x2,y1,y2,z)      (each `exp_bitsize`)
# - ciphertext c                (`LAMBDA` bits)
# - randomness r                (`LAMBDA` bits)

def keygen(gp_elt_bitsize):
    # NOTE: this `randfunc` (second argument) is not cryptographically secure
    # but we don't care because we just need some dummy inputs for our circuit
    key = ElGamal.generate(gp_elt_bitsize, lambda N : random.randbytes(N))
    # [p,g,pk:=y,sk:=x]
    q = key.p # modulus
    g1 = key.g
    g2 = IntegerGMP(random.randint(0,q-1))
    x1 = key.x
    # print("x1: {}".format(x1))
    sk = {}
    for str in ['x1','x2','y1','y2','z']:
        sk[str] = random.randint(0,q-1)
    c = pow(g1,sk['x1'],q) * pow(g2,sk['x2'],q) % q
    d = pow(g1,sk['y1'],q) * pow(g2,sk['y2'],q) % q
    h = pow(g1,sk['z'],q)

    pk = {'c': c, 'd': d, 'h': h, 'q': q, 'g1': g1, 'g2': g2}
    return pk,sk

def enc(pk,m):
    if len(pk) != 6:
        print("Enc failed, ill-formed pk {pk}")
        exit(-1)

    q = pk['q']

    k = IntegerGMP(random.randint(0,q-1))
    u1 = pow(pk['g1'],k,q)
    u2 = pow(pk['g2'],k,q)
    e = pow(pk['h'],k,q) * m % q
    # print("type(u1): {}, type(u2): {}, type(e): {}".format(type(u1), type(u2), type(e)))
    alpha = hashlib.sha3_256()
    alpha.update(u1.to_bytes())
    alpha.update(u2.to_bytes())
    alpha.update(e.to_bytes())
    # TODO is emp big- or little-endian?
    alpha = IntegerGMP(int.from_bytes(alpha.digest(),byteorder='big')) % q
    # print("type(pk['c']): {}, type(pk['d']): {}".format(type(pk['c']),type(pk['d'])))
    v = pow(pk['c'],k,q) * pow(pk['d'],(k*alpha),q) % q
    return (u1, u2, e, v)

# def extendedEuclid(a,b):
#     if a == 0:
#         return b,0,1
#     gcd,x1,y1 = extendedEuclid(b%a,a)
#     x = y1 - (b//a)*x1
#     y = x1
#     return gcd,x,y

# def inverse(i,p):
#     gcd,x,y = extendedEuclid(i,p)
#     return x

def dec(pk,sk,ctxt):
    if len(sk)!=5:
        print("Dec failed, ill-formed sk {sk}.")
        exit(-1)
    if len(ctxt)!=4:
        print("Dec failed, ill-formed ciphertext {ctxt}.")
        exit(-1)

    u1 = ctxt[0]
    u2 = ctxt[1]
    e = ctxt[2]
    v = ctxt[3]
    q = pk['q']
    alpha_prime = hashlib.sha3_256()
    alpha_prime.update(u1)
    alpha_prime.update(u2)
    alpha_prime.update(e)
    alpha_prime = int(alpha_prime.digest()) % q
    if pow(u1,sk['x1'],q) *  pow(u2,sk['x2'],q) * pow(pow(u1,sk['y1'],q) * pow(u2,sk['y2'],q),alpha_prime,q) % q != v:
        print("Decryption check failed! Aborting...")
        return -1
    return e*inverse(pow(u1,sk['z'],q), q)
    

# default params
# gp_elt_bitsize_default = 2048
gp_elt_bitsize_default = 256
secparam_default = 128
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate inputs to 2PC in BCS scheme",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '-g',
        '--gp-elt-bitsize',
        default=gp_elt_bitsize_default,
        type=int,
        required=False,
        dest="g",
        help="bit length of group elements"
    )
    # parser.add_argument(
    #     '-e',
    #     '--exp-bitsize',
    #     default=exp_bitsize_default,
    #     type=int,
    #     required=False,
    #     dest="e",
    #     help="bit length of exponents of group elements"
    # )
    parser.add_argument(
        '-n',
        '--secparam',
        default=secparam_default,
        type=int,
        required=False,
        dest="n",
        help="security parameter (for c,r length)"
    )
    args = parser.parse_args()

    print("Generating keys...")
    pk,sk = keygen(args.g)
    print(pk)
    print("done.\nGenerating r,c...")
    r = random.getrandbits(args.n)
    ctxt = enc(pk,0)
    print("done.")

    print("Writing to file...")
    with open("data/pk_H.txt","w") as f:
        for elt in pk.values():
            f.write(str(elt))
            f.write("\n")
    with open("data/sk_H.txt","w") as f:
        for elt in sk.values():
            f.write(str(elt))
            f.write("\n")
    with open("data/r_c.txt","w") as f:
        f.write(str(r))
        f.write("\n")
        for elt in ctxt:
            f.write(str(elt))
            f.write("\n")
    print("done.\n\nGoodbye!")
from z3 import *

# Scheme 타입 정의
Scheme, (BFV, BGV, CKKS) = EnumSort("Scheme", ["BFV", "BGV", "CKKS"])

# SecKey 타입 정의
SecKey = Datatype("SecKey")
SecKey.declare("secKeyGen")
SecKey.declare("none")  # None 상태
SecKey = SecKey.create()

# Context 타입 정의
Context = Datatype("Context")
Context.declare(
    "Context",
    ("Scheme", Scheme),
    ("N", IntSort()),
    ("MultDepth", IntSort()),
    ("SecKey", SecKey),
)
Context = Context.create()

Plain = Datatype("Plain")
Plain.declare("ecd", ("vals", SeqSort(IntSort())))
Plain = Plain.create()

Cipher = Datatype("Cipher")
Cipher.declare("enc", ("plain", Plain))
Cipher.declare("mul", ("fst", Cipher), ("snd", Cipher))
Cipher.declare("relin", ("prev", Cipher))
Cipher.declare("rescale", ("prev", Cipher))
Cipher = Cipher.create()

c = Const("c", Cipher)
ctxt = Const("ctxt", Context)

# size_of
size_of = RecFunction("size_of", Context, Cipher, IntSort())

RecAddDefinition(
    size_of,
    [ctxt, c],
    If(
        Cipher.is_enc(c),
        2,
        If(
            Cipher.is_mul(c),
            size_of(ctxt, Cipher.fst(c)) + size_of(ctxt, Cipher.snd(c)) - 1,
            If(Cipher.is_relin(c), 2, size_of(ctxt, Cipher.prev(c))),
        ),
    ),
)

# level_of
level_of = RecFunction("level_of", Context, Cipher, IntSort())

RecAddDefinition(
    level_of,
    [ctxt, c],
    If(
        Cipher.is_enc(c),
        Context.MultDepth(ctxt),
        If(
            Cipher.is_mul(c),
            If(
                level_of(ctxt, Cipher.fst(c)) < level_of(ctxt, Cipher.snd(c)),
                level_of(ctxt, Cipher.fst(c)),
                level_of(ctxt, Cipher.snd(c)),
            ),
            If(
                Cipher.is_relin(c),
                level_of(ctxt, Cipher.prev(c)),
                level_of(ctxt, Cipher.prev(c)) - 1,
            ),
        ),
    ),
)

solver = Solver()

encrypt_rule = ForAll(
    [c], If(Cipher.is_enc(c), SecKey.is_secKeyGen(Context.SecKey(ctxt)), True)
)

context_rule = If(
    Context.is_Context(ctxt),
    And(
        # MultDepth(ctxt) >= 0,
        Context.MultDepth(ctxt) >= 0,
        # Context.N(ctxt) > 0, N is a power of 2
        Or([Context.N(ctxt) == 2**i for i in range(10, 11)]),
    ),
    True,
)
solver.add(encrypt_rule)
solver.add(context_rule)

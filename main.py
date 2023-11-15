from spec_openfhe import *

# 객체 생성 및 쿼리 정의
p = Const("p", Plain)
c = Const("c", Cipher)
ctxt = Const("ctxt", Context)

# bug1 : level_of(ctxt, c) > 0 before Rescale(c)
# pre_cond = And(Context.MultDepth(ctxt) > 0, level_of(ctxt, c) == 0)

# bug2 : size_of(ctxt, c) == 2 before Rotate(c)
# pre_cond = And(Context.MultDepth(ctxt) > 0, size_of(ctxt, c) > 2)

# bug3 : length of vals <= N before Encode(p)
pre_cond = And(
    Context.Scheme(ctxt) == BGV,
    Length(Plain.vals(p)) > Context.N(ctxt),
)

solver.add(pre_cond)

# 식이 만족 가능한지 확인
if solver.check() == sat:
    print("Solution found!")
    print(solver.model())
else:
    print("No solution found.")

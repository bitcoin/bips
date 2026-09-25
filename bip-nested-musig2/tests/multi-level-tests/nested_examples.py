"""Signing examples expressed with the tree DSL.

In ``A(B,C),D``, A is the parent of B and C; A and D are siblings
under the implicit root. Parentheses enclose children, commas separate
siblings, and nesting adds levels. B, C, and D are leaf signers; A and
the root aggregate their children's contributions. Labels (including the
numbers below) name nodes; they are not keys or key indices.

Use ``print_tree(parse_forest("A(B,C),D"))`` to inspect the structure.
The parser displays the implicit root as ``ROOT``; vector paths use ``root``.
"""

from tree import *
from nested_musig2_exec import simulate_sign_test

tree1 = parse_forest("0(17(21(11(0(13(18)))),22(9(8(7,14(6(19)),12(1(4(2(3(15,16(5(10,20))))))))))))")
simulate_sign_test(tree1)

tree2 = parse_forest("4(5,0(6),2(7(3,8(1),9)))")
simulate_sign_test(tree2)

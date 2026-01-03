This is an adaptation of the MuSig2's partial signature forgery for the FROST protocol, described by Adam Gibson. You can find the [original write-up here](https://gist.github.com/AdamISZ/ca974ed67889cedc738c4a1f65ff620b).

In FROST signing, a malicious participant could forge the partial signature (i.e., _PartialSigVerify_ on it will succeed) of another participant without knowing their secret share, but only under the following conditions:
- The victim does not participate in the signing.
- The malicious participant impersonates the victim while also participating with their original share, making it appear as if two different participants are involved in the signing.

As a consequence, the malicious signing participant will be unable to create a valid partial signature for their original secret share.

1.
Key Setup: Let's consider a 3-of-5 FROST policy among a group of participants $\{P_1, P_2, P_3, P_4, P_5\}$ with the following details:

- The participant identifiers are $I = \{1, 2, 3, 4, 5\}$.
- Each participant's public share is denoted by $X_i \;\forall i \in I$.
- Each participant's secret share is denoted by $x_i \;\forall i \in I$.
- The threshold public key is denoted by $\tilde{X}$.

2.
Signing Setup: Assume we start a signing session with $S = \{P_1, P_2, P_4^*, P_5\}$. The adversarial participant will take the role of both $P_4^*$ and $P_5$, and will forge a partial signature on the public share $X_4$ without knowing the corresponding secret share $x_4$, on a given message $m$.
> [!NOTE]
>  In this scenario, the malicious participant $P_5$ is pretending to be the participant $P_4^*$ while also participating with their legitimate share. The real $P_4$ is unaware of this signing session.

3.
The adversary receives the nonces from other signing participants: $(R_{1,1}, R_{1,2}), (R_{2,1}, R_{2,2})$.

4.
The adversary sets aggregate partial nonces $R_1, R_2$ at random, without yet choose the individual pairs of partial nonces for $P_4^*$ and $P_5$. This is the 'cheat', which allows him to precalculate:

Calculate $\tilde{X} = \sum\limits_{i \in S} \lambda_{i, S} \cdot X_{i}$

Calculate $b = \mathbb{H}(\tilde{X}, R_1, R_2, m)$

Calculate $\tilde{R} = R_1 + b \cdot R_2$

Calculate $R_{1}^{*} = R_1 - \Sigma_{k=1}^2 R_{k,1}$

Calculate $R_{2}^{*} = R_2 - \Sigma_{k=1}^2 R_{k,2}$

The last two values $R_{i}^{*}$ are 'what is left over' to be filled in by the adversary's nonce values.

5.
To create nonces such that the forgery $s_4$ on $X_4$ verifies, the adversary does this:

Choose $s_4$ at random.

Calculate $Q = s_{4} \cdot G - \mathbb{H}\left(\tilde{X}, \tilde{R}, m\right)\lambda_{4, S}X_4$

Choose $R_{4,1}$ at random.

Calculate $R_{4,2} = b^{-1} \cdot \left (Q - R_{4,1}\right)$

Now, $s_4$ *will* successfully pass the *PartialSigVerify* for the public share $X_4$, message $m$, and the signer set $S$, but only if:

$R_{5,1} = R_{1}^{*} - R_{4,1}$
and
$R_{5,2} = R_{2}^{*} - R_{4,2}$

So, concluding the first communication round of the signing protocol, the adversary shares the rogue nonce values $R_{4,1}, R_{4,2}, R_{5,1}, R_{5,2}$ as calculated above.

Moving to the second communication round, the adversary can present the forged partial signature $s_4$. However, the adversary is unable to produce a valid $s_5$, as evident from examining the partial signature verification equation for $P_5$:

$$s_{5} \cdot G = R_{5,1} + b \cdot R_{5,2} + \mathbb{H}\left(\tilde{X}, \tilde{R}, m\right)\lambda_{5, S}X_5$$

The RHS is entirely fixed by the previous steps, and thus the LHS is a point whose discrete log cannot be extracted. In other words, the values $R_{5,1}, R_{5,2}$ were determined by the choices of nonces at other indices, and their secret values cannot be deduced (unlike in honest signing, where they are pre-determined by the signer). Therefore, **even though the adversary knows the secret share** $x_5$, **they are still unable to successfully complete the FROST protocol execution**.

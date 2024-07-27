#!/usr/bin/env python3

from typing import Iterable, List, Mapping, Tuple, Generator


def find_all(text: str, pattern: str, start: int = 0) -> Generator[int, None, None]:
    """Generates all the positions of `pattern` as a substring of `text`, starting from index at least `start`."""
    while True:
        start = text.find(pattern, start)
        if start == -1:
            return
        yield start
        start += len(pattern)


def find_first(text: str, start_pos: int, patterns: Iterable[str]) -> int:
    """Returns the position of the first occurrence of any of the elements in `patterns` as a substring of `text`,
    or -1 if none of the patterns is found."""
    matches = (text.find(x, start_pos) for x in patterns)
    return min((x for x in matches if x != -1), default=-1)


def find_key_end_position(desc: str, start_pos: int) -> int:
    """Assuming that `start_pos` is the beginning of a KEY expression (and not musig), finds the position of the end
    of the key expression, excluding (if present) the final derivation steps after an xpub. This is the information
    that goes into an entry of the vector of key information of the wallet policy."""

    has_orig_info = True if desc[start_pos] == '[' else False

    if has_orig_info:
        closing_bracket_pos = desc.find("]", start_pos)
        if closing_bracket_pos == -1:
            raise Exception("Invalid descriptor: could not find closing ']'")
        key_pos_start = closing_bracket_pos + 1
    else:
        key_pos_start = start_pos

    # find the earliest occurrence of ",", a ")" or a "/" (it must find at least 1)
    end_pos = find_first(desc, key_pos_start, [",", ")", "/"])
    if end_pos == -1:
        raise Exception(
            "Invalid descriptor: cannot find the end of key expression")

    return end_pos


class WalletPolicy(object):
    """Simple class to represent wallet policies. This is a toy implementation that does not parse the descriptor
    template. A more robust implementation would build the abstract syntax tree of the template and of the descriptor,
    allowing one to detect errors, and manipulate it semantically instead of relying on string manipulation."""

    def __init__(self, descriptor_template: str, keys_info: List[str]):
        self.descriptor_template = descriptor_template
        self.keys_info = keys_info

    def to_descriptor(self) -> str:
        """Converts a wallet policy into the descriptor (with the /<M,N> syntax, if present)."""

        desc = self.descriptor_template

        # replace each "/**" with "/<0;1>/*"
        desc = desc.replace("/**", "/<0;1>/*")

        # process all the @N expressions in decreasing order. This guarantees that string replacements
        # works as expected (as any prefix expression is processed after).
        for i in reversed(range(len(self.keys_info))):
            desc = desc.replace(f"@{i}", self.keys_info[i])

        # there should not be any remaining "@" expressions
        if desc.find("@") != -1:
            return Exception("Invalid descriptor template: contains invalid key index")

        return desc

    @classmethod
    def from_descriptor(cls, descriptor: str) -> 'WalletPolicy':
        """Converts a "reasonable" descriptor (with the /<M,N> syntax) into the corresponding wallet policy."""

        # list of pairs of integers, where the tuple (m,n) with m < n means a key expression starts at
        # m (inclusive) and at n (exclusive)
        key_expressions: List[Tuple[int, int]] = []

        key_with_orig_pos_start = None

        def parse_key_expressions(only_first=False, handle_musig=False):
            # Starting at the position in `key_with_orig_pos_start`, parses a number of key expressions, and updates
            # the `key_expressions` array accordingly.
            # If `only_first` is `True`, it stops after parsing a single key expression.
            # If `handle_musig` is `True`, and a key expression is a `musig` operator, it recursively parses
            # the keys in the musig expression. `musig` inside `musig` is not allowed.

            nonlocal key_with_orig_pos_start
            if key_with_orig_pos_start is None:
                raise Exception("Unexpected error")

            while True:
                if handle_musig and descriptor[key_with_orig_pos_start:].startswith("musig"):
                    closing_parenthesis_pos = find_first(
                        descriptor, key_with_orig_pos_start, [")"])
                    if closing_parenthesis_pos == -1:
                        raise Exception(
                            "Invalid descriptor: musig without closing parenthesis")
                    key_with_orig_pos_start = key_with_orig_pos_start + \
                        len("musig(")
                    parse_key_expressions(
                        only_first=False, handle_musig=False)

                    key_pos_end = closing_parenthesis_pos + 1
                else:
                    key_pos_end = find_key_end_position(
                        descriptor, key_with_orig_pos_start)
                    key_expressions.append(
                        (key_with_orig_pos_start, key_pos_end))

                if descriptor[key_pos_end] == '/':
                    # find the actual end (comma or closing parenthesis)
                    key_pos_end = find_first(
                        descriptor, key_pos_end, [",", ")"])
                    if key_pos_end == -1:
                        raise Exception(
                            "Invalid descriptor: unterminated key expression")

                if descriptor[key_pos_end] == ',':
                    # There is another key expression, repeat from after the comma
                    key_with_orig_pos_start = key_pos_end + 1
                else:
                    break

                if only_first:
                    break

        # operators for which the KEY is the first argument
        operators_key_first = ["pk", "pkh", "pk_h", "pk_k", "tr"]
        # operators for which the KEY is everything except the first argument
        operators_key_all_but_first = [
            "multi", "sortedmulti", "multi_a", "sortedmulti_a"]
        for op in operators_key_first + operators_key_all_but_first:
            for op_pos_start in find_all(descriptor, op + "("):

                # ignore if not a whole word (otherwise "sortedmulti" would be found inside "multi")
                if op_pos_start > 0 and 'a' <= desc[op_pos_start - 1] <= 'z':
                    continue

                if op in operators_key_all_but_first:
                    # skip the first argument (we know it's not a KEY expression, so it does not have a comma)
                    first_comma_pos = descriptor.find(",", op_pos_start)
                    if first_comma_pos == -1:
                        raise Exception(
                            "Invalid descriptor: multi, sortedmulti, multi_a and sortedmulti_a must have at least two arguments")
                    key_with_orig_pos_start = 1 + first_comma_pos
                else:
                    # other operators, the first argument is already a KEY expression
                    key_with_orig_pos_start = op_pos_start + len(op) + 1

                only_first = op in operators_key_first
                parse_key_expressions(
                    only_first=only_first, handle_musig=True)

        result: List[str] = []
        keys: List[str] = []
        keys_to_idx: Mapping[str, int] = {}

        prev_end = 0
        for start, end in sorted(key_expressions):
            result.append(descriptor[prev_end:start])

            key = descriptor[start:end]
            if key not in keys_to_idx:
                idx = len(keys)
                keys.append(key)
                keys_to_idx[key] = idx
            else:
                idx = keys_to_idx[key]
            result.append(f"@{idx}")

            prev_end = end

        result.append(descriptor[prev_end:])

        return cls("".join(result), keys)


if __name__ == "__main__":
    descriptors = [
        "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/**)",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/**,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/**))",
        "tr([12345678/44'/0'/0']xpub6BVZ6JrGsWsUbpP74S8rnz13hVFDtYtKyuTTEYPNSF6GFpDFpL1YXWg3BpwpUWAnsZZ7Qe3XKz7GL3BEx3RQVq61cxqSkjceq25S1xFKFVa,{pk(xpub6AGdromjXf5yf3m7ndaCoR9Ac3UjwTvQ7QQkZoyoh2vfGE9i1AwB2vCbvjTpBL1KRERUsGszg63SVNXsHZU3CiykQqtZPrdXKMdaG2vs6uu),pk(xpub6AnhdkteWC4kPQvkY3QQXGmDCMfmFoYzEQ7FwRFa4BQ1a22k4VL4BD3Jdcog2Sf2KzBscXXAdPRMgjCBDeq6bAryqnMaWX2FaVUGPxWMLDh)})",
        "tr(xpub6AEWqA1MNRzBBXenkug4NtNguDKTNcXoKQj8fU9VQyid38yikruFRffjoDm9UEaHGEJ6jQxjYdWWZRxR7Xy5ePrQNjohXJuNzkRNSiiBUcE,sortedmulti_a(2,[11223344/44'/0'/0']xpub6AyJhEKxcPaPnYNuA7VBeUQ24v6mEzzPSX5AJm3TSyg1Zsti7rnGKy1Hg6JAdXKF4QUmFZbby9p97AjBNm2VFCEec2ip5C9JntyxosmCeMW,xpub6AQVHBgieCHpGo4GhpGAo4v9v7hfr2Kr4D8ZQJqJwbEyZwtW3pWYSLRQyrNYbTzpoq6XpFtaKZGnEGUMtiydCgqsJDAZNqs9L5QDNKqUBsV))",
        "tr([11111111/44'/0'/0']xpub6CLZSUDtcUhJVDoPSY8pSRKi4W1RSSLBgwZ2AYmwTH9Yv5tPVFHZxJBUQ27QLLwHej6kfo9DQQbwaHmpXsQq59CjtsE2gNLHmojwgMrsQNe/**,{and_v(v:pk([22222222/44'/0'/0']xpub6CiztfGsUxmpwkWe6gvz8d5VHyFLDoiPpeUfWmQ2vWAhQL3Z1hhEc6PE4irFs4bzjS7dCB4yyinaubrCpFJq4bcKGCD4jjqTxaWiKAJ7mvJ/**),older(52596)),multi_a(2,[33333333/44'/0'/0']xpub6DTZd6od7is2wxXndmE7zaUifzFPwVKshVSGEZedfTJtUjfLyhy4hgCW15hvxRpGaDmtiFoJKaCEaSRfXrQBuYRx18zwquy46dwBsJnsrz2/**,[44444444/44'/0'/0']xpub6BnK4wFbPeLZM4VNjoUA4yLCru6kCT3bhDJNBhbzHLGp1fmgK6muz27h4drixJZeHG8vSS5U5EYyE3gE8ozG94iNg3NDYE8M5YafvhzhMR9/**)})",
        "tr(musig([33333333/44'/0'/0']xpub6DTZd6od7is2wxXndmE7zaUifzFPwVKshVSGEZedfTJtUjfLyhy4hgCW15hvxRpGaDmtiFoJKaCEaSRfXrQBuYRx18zwquy46dwBsJnsrz2,[44444444/44'/0'/0']xpub6BnK4wFbPeLZM4VNjoUA4yLCru6kCT3bhDJNBhbzHLGp1fmgK6muz27h4drixJZeHG8vSS5U5EYyE3gE8ozG94iNg3NDYE8M5YafvhzhMR9)/**,{and_v(v:pk([22222222/44'/0'/0']xpub6CiztfGsUxmpwkWe6gvz8d5VHyFLDoiPpeUfWmQ2vWAhQL3Z1hhEc6PE4irFs4bzjS7dCB4yyinaubrCpFJq4bcKGCD4jjqTxaWiKAJ7mvJ/**),older(52596)),pk([11111111/44'/0'/0']xpub6CLZSUDtcUhJVDoPSY8pSRKi4W1RSSLBgwZ2AYmwTH9Yv5tPVFHZxJBUQ27QLLwHej6kfo9DQQbwaHmpXsQq59CjtsE2gNLHmojwgMrsQNe/**)})",
    ]

    for desc in descriptors:
        # Demoes the conversion from a "sane" descriptor to a wallet policy
        print(f"Descriptor:\n{desc}")
        wp = WalletPolicy.from_descriptor(desc)
        print(f"Policy descriptor template:\n{wp.descriptor_template}")
        print(f"Keys:\n{wp.keys_info}")
        print("======================================================\n")

        # Converting back to descriptors also works, as long as we take care of /**
        assert wp.to_descriptor().replace("/<0;1>/*", "/**") == desc

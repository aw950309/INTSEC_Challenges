"""
Challenge 3.4 Solver
Goal 1: Find Bob's next OTP given f25a, cbc9.
Goal 2: Find Charlotte's potential next OTP (OTP3) given 1ccf, 1*** and n < 100.

Use tiny_h_otp.py to compute TinyH-OTP values.

Author: Alex Wagner
Version: 5.1
Date: 2025-12-17.
"""

import time

import tiny_h_otp

# Constants
MAX_16BIT = 0x10000  # 65536
MAX_STEP = 100
MAX_OTP_ATTEMPTS = 3


def find_mp_and_step_from_otps(otp1: str, otp2: str, tracker=None) -> tuple[str, int] | None:
    """
    Finds the Master Password (mp) given the two previous OTPs and
    that produces them using TinyH-OTP.
    Returns the found Master Password as a 4-hex-char string, or None if not found.

    So basically it checks for a masterpassword that can generate f25a.
    And if a masterpassword does indeed generate f25a. Then check if it also generates cbc9.
    """
    otp1_int = int(otp1, 16)
    otp2_int = int(otp2, 16)

    # Loop that iterates through every possible Master Password (guess_mp) from 0 to 65535.
    # It tries each guess to see if it produces the OTP
    for guess_mp_int in range(0, MAX_16BIT):

        # Helper: Need to convert the integer to a 4-character hex string so can check each possibility with tiny_h_otp.
        guess_mp_hex = f"{guess_mp_int:04x}"

        state = guess_mp_hex
        # Try each possible step n (0 to 99) where OTP1 could have been generated. And then check if the step n+1 produces OTP2.
        for n in range(MAX_STEP):
            state_int = (int(state, 16))
            if (state_int ^ guess_mp_int) == otp1_int:
                state_n1 = tiny_h_otp.TinyH(state)
                if (int(state_n1, 16) ^ guess_mp_int) == otp2_int:
                    print(f"Found Bob's Master Password: {guess_mp_hex}, at step n={n}")
                    return (guess_mp_hex, n)  # Return the found Master Password and step..

            state = tiny_h_otp.TinyH(state)  # Reuse for next iteration

    if tracker:
        tracker.finish()
    return None


def find_charlotte_solutions(otp1: str, otp2_prefix: str, max_step: int, tracker=None) -> list:
    """Find all master passwords that could produce Charlotte's OTPs.
    We know OTP1 = '1ccf' and OTP2 starts with '1'.
    For each possible master password, check if:
    1. It generates OTP1 at some step n
    2. The next step (n+1) generates an OTP starting with '1'
    3. If both match, compute OTP3 at step n+2 for Alice to use

    Returns list of (mp, step, otp2, otp3) tuples.
    Multiple solutions exist since we only know part of OTP2.
    """
    otp1_int = int(otp1, 16)
    solutions = []

    for mp_int in range(MAX_16BIT):
        mp_hex = f"{mp_int:04x}"
        state = mp_hex  #

        for n in range(max_step):
            state = tiny_h_otp.TinyH(state)
            state_int = int(state, 16)
            if (state_int ^ mp_int) == otp1_int:
                state_n1 = tiny_h_otp.TinyH(state)
                otp2_int = int(state_n1, 16) ^ mp_int
                otp2_hex = f"{otp2_int:04x}"

                if otp2_hex.startswith(otp2_prefix):
                    state_n2 = tiny_h_otp.TinyH(state_n1)
                    otp3_int = int(state_n2, 16) ^ mp_int
                    otp3_hex = f"{otp3_int:04x}"
                    solutions.append((mp_hex, n + 1, otp2_hex, otp3_hex))

    return solutions


def analyse_charlotte_results(solutions: list, max_attempts: int = 3) -> set[str]:
    """Analyse Charlotte's solutions and print statistics."""
    print(f"\nFound {len(solutions)} possible solutions for Charlotte.")

    # #Trouble shooting to see the OTP2 possibilites that match the OTP3 candidate.
    # #Print OTP2 -> OTP3 mapping
    # print(f"\nCharlotte's OTP candidates ({len(solutions)} solutions):")
    # print(f"  {'OTP2':<8} -> {'OTP3':<8} (mp, step)")
    # print(f"  {'-'*35}")
    # print(f"\nCharlotte's OTP2 -> OTP3 pairs:")
    # seen_pairs = set()
    # for sol in solutions:
    #     mp_hex, step, otp2, otp3 = sol
    #     pair = (otp2, otp3)
    #     if pair not in seen_pairs:
    #         seen_pairs.add(pair)
    #         print(f"  OTP2: {otp2} -> OTP3: {otp3}  (mp={mp_hex}, n={step})")

    unique_otp3s = set(sol[3] for sol in solutions)
    print(f"\nCharlotte's OTP3 candidates ({len(unique_otp3s)} unique):")
    for otp3 in sorted(unique_otp3s):
        print(f"  {otp3}")

    print(f"\nEach has probability: 1/{len(unique_otp3s)} = {1 / len(unique_otp3s):.0%}")

    success_probability = min(len(unique_otp3s), max_attempts) / len(unique_otp3s)
    print(f"\nWith {max_attempts} allowed attempts and {len(unique_otp3s)} candidates:")
    print(f"Probability of success: {max_attempts}/{len(unique_otp3s)} = {success_probability:.0%}")

    return unique_otp3s


# Following the main logic of my pseudo-code.
def main() -> None:
    """Solve OTP challenges for Bob and Charlotte using brute-force search."""

    # ===== PART A: Bob's OTP =====
    # Known: OTP1 = f25a, OTP2 = cbc9
    # Goal: Find OTP3 (Alice's login attempt)
    BOB_OTP1 = "f25a"
    BOB_OTP2 = "cbc9"

    print("Searching for Bob's master password...")

    # Step 1: Brute-force all 65536 master passwords to find one that produces f25a then cbc9
    if (result := find_mp_and_step_from_otps(BOB_OTP1, BOB_OTP2, tracker=None)) is None:
        print("Error: Could not find a master password for the given OTPs.")
    else:
        master_password, found_step = result
        STEPS_AFTER_FIRST_OBSERVED = 2
        # Step 2: Compute OTP3 using the found master password at step n+2.
        otp3 = tiny_h_otp.TinyH_OTP(master_password, found_step + STEPS_AFTER_FIRST_OBSERVED)
        print(f"Bob's next OTP is: {otp3}")

    # ===== PART B: Charlotte's OTP =====
    # Known: OTP1 = 1ccf, OTP2 starts with '1', step < 100 (used less than 100 times).
    # Goal: Find all possible OTP3 values (partial info = multiple solutions).

    CHARLOTTE_OTP1 = "1ccf"
    CHARLOTTE_OTP2_PREFIX = "1"

    # Step 1: Find all master passwords where OTP1 = 1ccf and OTP2 starts with '1'
    print("\nSearching for Charlotte's solutions...")
    solutions = find_charlotte_solutions(CHARLOTTE_OTP1, CHARLOTTE_OTP2_PREFIX, MAX_STEP, tracker=None)

    # Step 2: Analyse results and compute success probability (Alice can try 3 times).
    analyse_charlotte_results(solutions, max_attempts=MAX_OTP_ATTEMPTS)


if __name__ == "__main__":
    start_time = time.time()
    main()
    elapsed_time = time.time() - start_time
    print(f"\nProgram ran: {elapsed_time:.2f} seconds")

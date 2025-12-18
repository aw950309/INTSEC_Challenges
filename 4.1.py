"""Challenge 4.1 (Simple):
Fictional scenario: Imagine I wrote a game for the student of the course.
I put it on a linux server where all students have an account and are part of the group students. Here are the files related to the game:
- _ _ _ _ _ _ _ _ _ nicolas students game-binary
- _ _ _ _ _ _ _ _ _ nicolas students high-scores.txt
Set the rights to let anyone in the group "students" play the game and save their best score, without allowing anyone to cheat. (Apply the principle of least privilege and Fail-safe defaults).
 You can assume that a process regularly saves and flushes the content of high-scores.txt. (Credit for this problem: Alan Davidson.)"""

def main():
    print("This is a placeholder for Challenge 4.1 solution.")
    print("To solve the challenge, set appropriate file permissions on the game-binary and high-scores.txt files.")
    print("For example, you might use chmod to set the correct permissions:")
    print("  chmod 750 game-binary")
    print("  chmod 640 high-scores.txt")
    print("Ensure that the owner is 'nicolas' and the group is 'students'.")

if __name__ == "__main__":
    main()


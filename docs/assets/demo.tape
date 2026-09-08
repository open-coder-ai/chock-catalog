# chock-catalog -- hero demo GIF
#
# Onboard a repo, get blocked committing a secret, fix it, then get blocked again for
# committing straight to main. Every command in this tape is real: rendering it re-runs
# `chock` against a throwaway repo and records what the tools actually print.
#
# Render:  vhs docs/assets/demo.tape        # writes docs/assets/demo.gif

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 640
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 24

# --- hidden setup: a throwaway repo, off main, so the branch-protection payoff at the
# end is the first time that gate fires --------------------------------------------
Hide
Type "cd $(mktemp -d)"
Enter
Type "export HOME=$(mktemp -d)"
Enter
Type "git -c init.defaultBranch=main init -q demo && cd demo"
Enter
Type "git config user.email demo@example.com && git config user.name Demo"
Enter
Type "git checkout -q -b feature/demo"
Enter
Type "clear"
Enter
Show

# --- 1. Onboard, adopt two guardrails from the catalog ---
Type "chock init ."
Enter
Sleep 700ms

Type "chock add scan-secrets"
Enter
Sleep 2600ms

Type "chock add protect-main-branch"
Enter
Sleep 2600ms

Type "chock sync --repo ."
Enter
Sleep 700ms

# --- 2. Commit a credential -> blocked ---
Type@15ms `echo 'AWS_KEY=AKIAIOSFODNN7EXAMPLE' > config.py && git add config.py && git commit -m "add config"`
Enter
Sleep 3500ms

# --- 3. Read it from the environment instead -> passes ---
Type@15ms `echo 'AWS_KEY = os.environ["AWS_KEY"]' > config.py && git add config.py && git commit -m "add config"`
Enter
Sleep 1700ms

# --- 4. Same repo, on main -> blocked, no secret involved this time ---
Type "git checkout -b main"
Enter
Sleep 500ms

Type "git commit --allow-empty -m notes"
Enter
Sleep 3500ms

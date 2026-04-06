Output docs/check-deps-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 600
Set Theme "Dracula"
Set Padding 20

Env PS1 "$ "

# Show the lock file first
Type "cat package-lock.json | head -10"
Enter
Sleep 1s

# Run check-deps
Type "runner-guard check-deps ."
Enter
Sleep 3s

Sleep 2s

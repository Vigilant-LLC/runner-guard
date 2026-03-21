Output docs/demo.gif
Set Shell "bash"
Set Width 1100
Set Height 850
Set FontSize 16
Set Theme "Dracula"
Set Padding 30
Set Framerate 24
Set TypingSpeed 80ms

Env PS1 "$ "

Sleep 2s

# Show the full demo scan (all scenarios)
Type "runner-guard demo"
Sleep 1.5s
Enter
Sleep 20s

# Pause at the end so viewer can read the summary
Sleep 5s

# Now show scanning a clean repo
Type "runner-guard scan ."
Sleep 1.5s
Enter
Sleep 5s

Output docs/menu-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 600
Set Theme "Dracula"
Set Padding 20

# Hide prompt by using a clean PS1
Env PS1 "$ "

Type "runner-guard"
Enter
Sleep 1s

# Select option 1 - single repo scan
Type "1"
Enter
Sleep 500ms

# Select local directory
Type "a"
Enter
Sleep 500ms

# Confirm default path
Type "y"
Enter
Sleep 3s

Sleep 2s

Output docs/batch-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 600
Set Theme "Dracula"
Set Padding 20

Env PS1 "$ "

# Show the repos file first
Type "cat repos.txt"
Enter
Sleep 1s

# Run batch scan
Type "runner-guard scan --repos repos.txt --concurrency 3"
Enter
Sleep 8s

Sleep 2s

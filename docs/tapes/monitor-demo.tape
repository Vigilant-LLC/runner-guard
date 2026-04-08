Output docs/monitor-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 500
Set Theme "Dracula"
Set Padding 20

Env PS1 "$ "

# Show monitor help briefly
Type "runner-guard monitor --help"
Enter
Sleep 3s

# Start monitoring
Type "runner-guard monitor . --interval 300"
Enter
Sleep 6s

# Ctrl+C to stop
Ctrl+C
Sleep 2s

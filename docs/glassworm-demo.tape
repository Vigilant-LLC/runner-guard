Output docs/glassworm-demo.gif
Set Shell "bash"
Set Width 1100
Set Height 850
Set FontSize 16
Set Theme "Dracula"
Set Padding 30
Set Framerate 24
Set TypingSpeed 80ms

Env PS1 "$ "

# Title pause so viewer can orient
Sleep 2s

# Run the GlassWorm demo scenario
Type "runner-guard demo --scenario glassworm"
Sleep 1.5s
Enter
Sleep 12s

# Let the viewer read the findings
Sleep 5s

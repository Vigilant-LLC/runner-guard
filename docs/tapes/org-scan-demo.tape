Output docs/org-scan-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 600
Set Theme "Dracula"
Set Padding 20

Env PS1 "$ "

# Scan an organization
Type "runner-guard scan --org sigstore --concurrency 5"
Enter
Sleep 15s

Sleep 3s

# Generate a real animated GIF of the demo with charmbracelet/vhs:
#
#   brew install vhs        # or see https://github.com/charmbracelet/vhs
#   npm run build
#   vhs assets/demo.tape    # -> writes assets/demo.gif
#
Output assets/demo.gif

Set Shell "bash"
Set FontSize 17
Set Width 1180
Set Height 700
Set Padding 26
Set Theme "Dracula"

Type "npm run demo" Sleep 500ms Enter
Sleep 5s

Type "npm run demo:enforce" Sleep 500ms Enter
Sleep 5s

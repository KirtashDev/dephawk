# The animated demo in the README, recorded with charmbracelet/vhs:
#
#   brew install vhs        # or see https://github.com/charmbracelet/vhs
#   npm run build
#   vhs assets/demo.tape    # -> writes assets/demo.gif
#
# Two acts, both real: dephawk watching a malicious dependency, then blocking
# it. Nothing is staged — the output is whatever the current build prints.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1240
Set Height 720
Set Padding 22
Set Theme "Dracula"
Set TypingSpeed 45ms
Set Framerate 20

# Setup, hidden from the recording: a throwaway copy of examples/demo with this
# build installed as a local `dephawk` binary, so the commands on screen are the
# ones a user would really type. HOME is neutral so the report reads `/Users/you`
# rather than naming whoever recorded it, and NPM_TOKEN exists so there is a
# secret to find. Nothing here leaves the machine — see the sample's own header.
Hide
Type "REPO=$PWD; DEMO=/tmp/dephawk-demo-recording" Enter
Type "rm -rf $DEMO && mkdir -p $DEMO/node_modules/.bin && cp -r examples/demo/* $DEMO/" Enter
Type "ln -s $REPO/dist/cli.js $DEMO/node_modules/.bin/dephawk" Enter
Type "cd $DEMO && export PATH=$PWD/node_modules/.bin:$PATH" Enter
Type "export HOME=/Users/you NPM_TOKEN=npm_demo_fake_token PS1='$ '" Enter
Type "clear" Enter
Show

# Act I — see it. One dependency, and everything it quietly does.
Sleep 1s
Type "dephawk run node index.js" Sleep 400ms Enter
Sleep 9s

# Act II — block it. Same run under enforce, ending on the CI exit code.
Type "dephawk run --enforce --fail-on blocked node index.js" Sleep 400ms Enter
Sleep 8s
Type "echo CI exit code: $?" Sleep 300ms Enter
Sleep 3s

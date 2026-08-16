# The animated demo in the README, recorded with charmbracelet/vhs:
#
#   brew install vhs        # or see https://github.com/charmbracelet/vhs
#   npm run build
#   vhs assets/demo.tape    # -> writes assets/demo.gif
#
# Two acts, both real: dephawk watching a malicious dependency, then blocking
# it. Nothing is staged — the output is whatever the current build prints, and
# the sample's twelve calls are what produce the twelve lines on screen.
#
# The frame is sized to the report rather than to a round number: at 1100px the
# longest line (~98 columns) still fits, and GitHub scales it down less than a
# 1240px capture would, so the text stays legible in the README column.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 700
Set Padding 22
Set Theme "Dracula"
Set TypingSpeed 35ms
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

# Act I — see it. One dependency: your SSH keys, your browser's saved passwords,
# a wallet, an AI-agent hook it plants in .claude to re-run on open (the 2026 keyv
# worm's move), your npm token, Node's raw internal bindings, a WebAssembly
# payload, a backdoor port, a shell-out and an exfil socket. Every one named.
Sleep 800ms
Type "dephawk run node index.js" Sleep 400ms Enter
Sleep 7s

# Act II — block it. Same run under enforce, ending on the CI exit code.
Type "# every call attributed, the worm's editor hook included. now refuse them:" Sleep 200ms Enter
Sleep 700ms
Type "dephawk run --enforce --fail-on blocked node index.js" Sleep 400ms Enter
Sleep 7s
Type "echo CI exit code: $?" Sleep 300ms Enter
Sleep 3s

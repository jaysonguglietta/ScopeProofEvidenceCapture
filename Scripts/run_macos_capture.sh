#!/bin/zsh
set -euo pipefail

project_root="${0:A:h:h}"
build_script="$project_root/Scripts/build_macos_capture.sh"
built_app="$project_root/DerivedData/Scopeproof Capture.app"
applications_directory="${SCOPEPROOF_LOCAL_APPLICATIONS_DIR:-$HOME/Applications}"
installed_app="$applications_directory/Scopeproof Capture.app"
launch_app=true

if (( $# > 1 )) || { (( $# == 1 )) && [[ "$1" != "--no-launch" ]]; }; then
  echo "Usage: ./Scripts/run_macos_capture.sh [--no-launch]" >&2
  exit 2
fi
if (( $# == 1 )); then
  launch_app=false
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Scopeproof Capture requires macOS 14 or newer." >&2
  exit 1
fi

if ! command -v swift >/dev/null 2>&1; then
  echo "The Swift toolchain is required to build Scopeproof Capture." >&2
  echo "Run 'xcode-select --install', finish the installation, and try again." >&2
  exit 1
fi

echo "Building Scopeproof Capture…"
"$build_script"

if [[ ! -d "$built_app" ]]; then
  echo "The build finished without producing $built_app." >&2
  exit 1
fi

mkdir -p "$applications_directory"

# ditto safely updates an existing local installation without requiring an
# administrator password. Local installations live in the current user's
# Applications folder so they do not affect other accounts on the Mac.
if [[ "$launch_app" == true ]] && /usr/bin/pgrep -x ScopeproofCapture >/dev/null 2>&1; then
  /usr/bin/pkill -x ScopeproofCapture
fi
/usr/bin/ditto "$built_app" "$installed_app"

echo "Installed Scopeproof Capture in $applications_directory"
if [[ "$launch_app" == true ]]; then
  echo "Launching the menu-bar app…"
  /usr/bin/open "$installed_app"

  echo "Look for the shield in the menu bar. On the first capture, allow"
  echo "Screen Recording when macOS asks; then quit and reopen the app once."
fi

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

install_staging_root="$(mktemp -d "$applications_directory/.scopeproof-install.XXXXXX")"
staged_install="$install_staging_root/Scopeproof Capture.app"
previous_install="$applications_directory/.Scopeproof Capture.app.previous.$$"
cleanup_install() {
  /bin/rm -rf -- "$install_staging_root"
  if [[ -e "$previous_install" ]]; then
    if [[ ! -e "$installed_app" ]]; then mv "$previous_install" "$installed_app"
    else /bin/rm -rf -- "$previous_install"
    fi
  fi
}
trap cleanup_install EXIT INT TERM

# Stop the exact executable before replacement even with --no-launch. User data
# remains outside the application bundle and is never touched by this script.
if /usr/bin/pgrep -x ScopeproofCapture >/dev/null 2>&1; then
  /usr/bin/pkill -x ScopeproofCapture
  for _ in {1..20}; do
    if ! /usr/bin/pgrep -x ScopeproofCapture >/dev/null 2>&1; then break; fi
    /bin/sleep 0.1
  done
  if /usr/bin/pgrep -x ScopeproofCapture >/dev/null 2>&1; then
    echo "Scopeproof Capture did not quit; the existing app was not replaced." >&2
    exit 1
  fi
fi

# Copy and verify a fresh staged bundle, then replace the prior installation by
# same-volume rename. This prevents obsolete resources from surviving a merge.
/usr/bin/ditto "$built_app" "$staged_install"
/usr/bin/codesign --verify --deep --strict "$staged_install"
[[ "$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$staged_install/Contents/Info.plist")" == "com.scopeproof.capture" ]]
[[ "$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - "$staged_install/Contents/Info.plist")" == "14.0" ]]
if [[ -e "$installed_app" ]]; then mv "$installed_app" "$previous_install"; fi
if ! mv "$staged_install" "$installed_app"; then
  if [[ -e "$previous_install" ]]; then mv "$previous_install" "$installed_app"; fi
  exit 1
fi
if [[ -e "$previous_install" ]]; then /bin/rm -rf -- "$previous_install"; fi
/usr/bin/codesign --verify --deep --strict "$installed_app"

echo "Installed Scopeproof Capture in $applications_directory"
if [[ "$launch_app" == true ]]; then
  echo "Launching the menu-bar app…"
  /usr/bin/open "$installed_app"

  echo "Look for the shield in the menu bar. On the first capture, allow"
  echo "Screen Recording when macOS asks; then quit and reopen the app once."
fi

#!/bin/bash
# audio-idle-inhibit — hold a logind idle inhibitor while audio is playing.
#
# Drop-in replacement for sway-audio-idle-inhibit (AUR-only, not packaged on
# Debian). It uses the same mechanism: a logind Inhibit("idle", "block")
# lock, which swayidle 1.8 watches (the BlockInhibited property) and which
# suspends all of its timeouts (dim, lock, power-off-monitors) while held.
#
# Unlike a Wayland idle inhibitor bound to a surface (e.g. waybar's
# idle_inhibitor), this works even when the video is fullscreen: niri ignores
# inhibitors whose surface is not visible on screen (niri issue #2028).

POLL_INTERVAL=2

# True if any playback or capture stream is currently running.
audio_running() {
    pw-dump 2>/dev/null | jq -e '
        [.[] | select(.type == "PipeWire:Interface:Node")
         | select(.info.props["media.class"]? == "Stream/Input/Audio"
               or  .info.props["media.class"]? == "Stream/Output/Audio")
         | select(.info.state == "running")
        ] | length > 0' > /dev/null
}

# Inner mode: poll until playback stops, then exit so systemd-inhibit
# releases the lock. Exiting is enough — the inhibitor is held by an FD
# owned by the systemd-inhibit process wrapping this child.
if [ "${1:-}" = "--wait" ]; then
    while audio_running; do
        sleep "$POLL_INTERVAL"
    done
    exit 0
fi

# Single instance per session (survives compositor restarts otherwise).
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/audio-idle-inhibit.lock"
flock -n 9 || exit 0

while :; do
    if audio_running; then
        echo "audio-idle-inhibit: holding logind idle inhibitor"
        # Blocks (holding the inhibitor) until the --wait child exits,
        # i.e. until playback has stopped. logind then emits
        # PropertiesChanged and swayidle re-arms its timeouts.
        systemd-inhibit --what=idle \
                        --who="audio-idle-inhibit" \
                        --why="Audio is playing" \
                        --mode=block \
                        "$0" --wait
        echo "audio-idle-inhibit: released logind idle inhibitor"
    else
        sleep "$POLL_INTERVAL"
    fi
done

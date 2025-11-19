#!/bin/bash

# 2-minute (120s) timeout to dim the screen
# 4-minute (240s) timeout to lock the screen
# 5-minute (300s) timeout to turn off the monitors

exec swayidle -w \
    timeout 120 'brightnessctl s && brightnessctl set 1%' \
    timeout 240 'gtklock' \
    timeout 300 'niri msg action power-off-monitors' \
    resume 'brightnessctl r && niri msg action power-on-monitors' \
    before-sleep 'gtklock'

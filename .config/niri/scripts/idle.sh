#!/bin/bash

exec swayidle -w \
	timeout 240 'niri msg action power-off-monitors"' \
		resume 'niri msg action power-on-monitors"' \
	before-sleep 'gtklock' \
        lock 'gtklock'

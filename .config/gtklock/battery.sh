#!/bin/bash

# Detect battery path (usually BAT0 or BAT1)
if [ -d /sys/class/power_supply/BAT0 ]; then
    BAT="BAT0"
elif [ -d /sys/class/power_supply/BAT1 ]; then
    BAT="BAT1"
else
    echo "No Batt"
    exit 0
fi

# Read energy level and status
capacity=$(cat /sys/class/power_supply/$BAT/capacity)
status=$(cat /sys/class/power_supply/$BAT/status)

# Set icon based on status and capacity
if [ "$status" = "Charging" ]; then
    icon="⚡"
else
    if [ "$capacity" -ge 90 ]; then
        icon=" "   # Full
    elif [ "$capacity" -ge 60 ]; then
        icon=" "   # High
    elif [ "$capacity" -ge 40 ]; then
        icon=" "   # Medium
    elif [ "$capacity" -ge 10 ]; then
        icon=" "   # Low
    else
        icon=" "   # Critical
    fi
fi

# Print the final string
echo "$icon $capacity%"

#!/usr/bin/env bash

case "$1" in 
focus-workspace)
    niri msg action "$@" && pkill -SIGRTMIN+8 waybar;;
up)
    niri msg action focus-workspace-up && pkill -SIGRTMIN+8 waybar;;
down)
    niri msg action focus-workspace-down && pkill -SIGRTMIN+8 waybar;;
*)
    glyphs=""
    workspace_str=" " 
    
    # Lấy cả danh sách workspace và windows để so khớp
    # Logic lọc: Giữ lại workspace nếu (nó đang Active) HOẶC (ID của nó có xuất hiện trong danh sách windows)
    data=$(jq -n --argjson ws "$(niri msg -j workspaces)" --argjson wins "$(niri msg -j windows)" \
        '$ws[] | select(.output == "'"$1"'") | select(.is_active or (.id as $id | $wins | any(.workspace_id == $id))) | .is_active')

    for ws in $data; do
        workspace_str="$workspace_str$( if [ "$ws" = "true" ]; then
                 echo "<span color='#e8fc99'>${glyphs:0:1}</span>";
            else 
                 echo "${glyphs:1:1}"; fi)  "
    done
    
    # Lấy tên workspace đang active (để hiển thị tooltip)
    name=$(niri msg -j workspaces | jq -r ".[] | select(.output == \"$1\" and .is_active == true) | .name")
    echo -e "{\"text\":\"${workspace_str}\", \"tooltip\":\"Active workspace name: ${name}\"}"
esac

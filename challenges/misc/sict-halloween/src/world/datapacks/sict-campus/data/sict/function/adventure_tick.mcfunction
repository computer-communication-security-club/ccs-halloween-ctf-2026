gamemode adventure @a[gamemode=!adventure]
execute as @a[tag=!sict_front_spawn,nbt=!{Health:0.0f}] in minecraft:overworld run function sict:server_spawn_player
function sict:adventure_button_tick
team join sict_players @a[team=!sict_players]

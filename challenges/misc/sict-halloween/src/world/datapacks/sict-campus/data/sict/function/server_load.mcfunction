function sict:relocate_button
function sict:secret_close
execute unless data storage sict:server initialized run function sict:server_first_start
gamerule minecraft:pvp false
team add sict_players
team modify sict_players collisionRule never
team modify sict_players friendlyFire false

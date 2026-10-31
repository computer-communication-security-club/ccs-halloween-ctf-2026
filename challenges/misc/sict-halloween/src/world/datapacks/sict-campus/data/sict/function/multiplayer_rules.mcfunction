# Shared adventure map protection. Minecraft 26.3 uses gamerules for PvP.
# Keep the Halloween atmosphere fixed, including when players use beds.
gamerule minecraft:advance_weather false
gamerule minecraft:advance_time false
gamerule minecraft:players_sleeping_percentage 101
weather thunder
time set midnight
gamerule minecraft:pvp false
gamerule minecraft:mob_griefing false
gamerule minecraft:tnt_explodes false
gamerule minecraft:fire_spread_radius_around_player 0
gamerule minecraft:projectiles_can_break_blocks false
gamerule minecraft:command_blocks_work false
gamerule minecraft:allow_entering_nether_using_portals false
gamerule minecraft:locator_bar false
gamerule minecraft:show_advancement_messages false
team add sict_players
team modify sict_players collisionRule never
team modify sict_players friendlyFire false
worldborder center -137 11
worldborder set 256

execute as @e[type=minecraft:interaction,tag=sict_entry_button] if data entity @s interaction run function sict:adventure_entry_press
execute as @e[type=minecraft:interaction,tag=sict_exit_button] if data entity @s interaction run function sict:adventure_exit_press

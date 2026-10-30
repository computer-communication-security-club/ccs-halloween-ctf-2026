effect give @a[x=-204,y=54,z=-77,dx=134,dy=90,dz=176,gamemode=adventure] minecraft:saturation 1 0 true
function sict:adventure_button_tick
team join sict_players @a[team=!sict_players]

tag @s add sict_checked
execute store success score @s sict_shot on origin if entity @s[type=minecraft:player,scores={sict_pk=10},x=-126,y=77,z=-50,dx=2,dy=2,dz=2]
execute if score @s sict_shot matches 1 run tag @s add sict_ball
scoreboard players reset @s sict_shot

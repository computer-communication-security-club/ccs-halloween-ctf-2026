execute as @e[type=minecraft:interaction,tag=ctf_fragment1] if data entity @s interaction on target run function sict:ctf/claim1
execute as @e[type=minecraft:interaction,tag=ctf_fragment1] if data entity @s interaction run data remove entity @s interaction
execute as @e[type=minecraft:interaction,tag=ctf_fragment2] if data entity @s interaction on target run function sict:ctf/claim2
execute as @e[type=minecraft:interaction,tag=ctf_fragment2] if data entity @s interaction run data remove entity @s interaction
execute as @e[type=minecraft:interaction,tag=ctf_fragment4] if data entity @s interaction on target run function sict:ctf/claim4
execute as @e[type=minecraft:interaction,tag=ctf_fragment4] if data entity @s interaction run data remove entity @s interaction
execute as @e[type=minecraft:interaction,tag=ctf_briefing] if data entity @s interaction on target run function sict:ctf/briefing
execute as @e[type=minecraft:interaction,tag=ctf_briefing] if data entity @s interaction run data remove entity @s interaction
execute as @e[type=minecraft:interaction,tag=ctf_start] if data entity @s interaction on target run function sict:ctf/start
execute as @e[type=minecraft:interaction,tag=ctf_start] if data entity @s interaction run data remove entity @s interaction
execute as @a[scores={sict_pk=1},x=-130,y=73,z=-39,dx=0,dy=0,dz=0] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad1
execute as @a[scores={sict_pk=2},x=-133,y=74,z=-41,dx=0,dy=0,dz=0] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad2
execute as @a[scores={sict_pk=3},x=-136,y=74,z=-43,dx=0,dy=0,dz=0] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad3
execute as @a[scores={sict_pk=4},x=-134,y=75,z=-46,dx=0,dy=0,dz=0] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad4
execute as @a[scores={sict_pk=5},x=-131,y=75,z=-49,dx=0,dy=0,dz=0] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad5
execute as @a[scores={sict_pk=6},x=-133,y=76,z=-52,dx=0,dy=0,dz=0] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad6
execute as @a[scores={sict_pk=7},x=-130,y=76,z=-55,dx=0,dy=0,dz=0] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad7
execute as @a[scores={sict_pk=8},x=-128,y=77,z=-52,dx=0,dy=0,dz=0] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad8
execute as @a[scores={sict_pk=9},x=-126,y=77,z=-50,dx=2,dy=0,dz=2] at @s if block ~ ~-1 ~ minecraft:orange_concrete run function sict:ctf/pad9
execute as @e[type=minecraft:interaction,tag=ctf_ball_rack] if data entity @s interaction on target run function sict:ctf/refill
execute as @e[type=minecraft:interaction,tag=ctf_ball_rack] if data entity @s interaction run data remove entity @s interaction
execute as @a[x=-131,y=72,z=-36,dx=2,dy=0,dz=2] at @s if block ~ ~-1 ~ minecraft:gold_block unless score @s sict_pk matches 1..10 run function sict:ctf/start
execute as @a[scores={sict_pk=2..10},x=-138,y=70,z=-59,dx=20,dy=20,dz=28] store result score @s sict_y run data get entity @s Pos[1] 10
execute as @a[scores={sict_pk=2..10},x=-138,y=70,z=-59,dx=20,dy=20,dz=28] if score @s sict_y matches ..721 run function sict:ctf/fall
scoreboard players remove @a[scores={sict_refill=1..}] sict_refill 1
execute as @e[type=minecraft:snowball,tag=!sict_checked,x=-142,y=70,z=-62,dx=26,dy=13,dz=34] run function sict:ctf/check_ball
execute as @e[type=minecraft:snowball,tag=sict_ball,x=-125,y=78,z=-55,dx=0,dy=0,dz=2] at @s run function sict:ctf/score_ball

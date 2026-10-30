fill -181 71 -66 -84 71 -66 minecraft:stone_bricks
fill -181 72 -66 -84 74 -66 minecraft:iron_bars
fill -181 71 55 -84 71 55 minecraft:stone_bricks
fill -181 72 55 -84 74 55 minecraft:iron_bars
fill -181 71 -66 -181 71 55 minecraft:stone_bricks
fill -181 72 -66 -181 74 55 minecraft:iron_bars
fill -84 71 -66 -84 71 55 minecraft:stone_bricks
fill -84 72 -66 -84 74 55 minecraft:iron_bars
fill -133 72 5 -131 74 5 minecraft:light_blue_stained_glass
fill -127 72 5 -125 74 5 minecraft:light_blue_stained_glass
fill -158 72 -33 -155 74 -33 minecraft:light_blue_stained_glass
fill -107 72 50 -105 73 50 minecraft:light_blue_stained_glass
fill -178 65 33 -174 69 73 minecraft:stone_bricks
fill -177 66 33 -175 68 72 minecraft:air
setblock -176 69 34 minecraft:sea_lantern
setblock -176 69 38 minecraft:sea_lantern
setblock -176 69 42 minecraft:sea_lantern
setblock -176 69 46 minecraft:sea_lantern
setblock -176 69 50 minecraft:sea_lantern
setblock -176 69 54 minecraft:sea_lantern
setblock -176 69 58 minecraft:sea_lantern
setblock -176 69 62 minecraft:sea_lantern
setblock -176 69 66 minecraft:sea_lantern
setblock -176 69 70 minecraft:sea_lantern
fill -177 65 33 -167 65 35 minecraft:stone_bricks
fill -177 66 33 -167 74 35 minecraft:air
fill -175 65 33 -175 65 35 minecraft:stone_bricks
setblock -175 66 33 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -175 66 34 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -175 66 35 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -175 70 34 minecraft:sea_lantern
fill -174 65 33 -174 66 35 minecraft:stone_bricks
setblock -174 67 33 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -174 67 34 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -174 67 35 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -174 71 34 minecraft:sea_lantern
fill -173 65 33 -173 67 35 minecraft:stone_bricks
setblock -173 68 33 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -173 68 34 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -173 68 35 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -173 72 34 minecraft:sea_lantern
fill -172 65 33 -172 68 35 minecraft:stone_bricks
setblock -172 69 33 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -172 69 34 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -172 69 35 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -172 73 34 minecraft:sea_lantern
fill -171 65 33 -171 69 35 minecraft:stone_bricks
setblock -171 70 33 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -171 70 34 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -171 70 35 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -171 74 34 minecraft:sea_lantern
fill -170 65 33 -170 70 35 minecraft:stone_bricks
setblock -170 71 33 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -170 71 34 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -170 71 35 minecraft:stone_brick_stairs[facing=east,half=bottom,shape=straight]
setblock -170 75 34 minecraft:sea_lantern
fill -169 65 33 -167 71 35 minecraft:stone_bricks
fill -177 72 32 -170 73 32 minecraft:iron_bars
setblock -176 70 34 minecraft:sea_lantern
setblock -168 75 34 minecraft:sea_lantern
fill -180 64 73 -173 69 73 minecraft:mossy_stone_bricks
fill -179 63 74 -174 63 75 minecraft:mossy_cobblestone
fill -179 64 74 -174 65 74 minecraft:mossy_stone_bricks
fill -177 64 75 -175 64 75 minecraft:stone_brick_stairs[facing=north,half=bottom,shape=straight]
fill -177 65 74 -175 65 74 minecraft:stone_brick_stairs[facing=north,half=bottom,shape=straight]
fill -177 66 74 -175 68 75 minecraft:air
setblock -179 66 74 minecraft:stone_button[face=wall,facing=south,powered=false]
setblock -179 67 74 minecraft:oak_leaves[persistent=true]
setblock -179 68 74 minecraft:oak_leaves[persistent=true]
setblock -177 67 70 minecraft:stone_button[face=wall,facing=east,powered=false]
setblock -178 68 74 minecraft:light[level=15]
setblock -174 68 74 minecraft:light[level=15]
setblock -179 66 74 minecraft:oak_leaves[persistent=true]
fill -182 63 74 -180 64 75 minecraft:mossy_cobblestone
fill -181 64 73 -181 67 73 minecraft:mossy_cobblestone
setblock -181 66 74 minecraft:mossy_cobblestone
setblock -181 65 74 minecraft:stone_button[face=ceiling,facing=north,powered=false]
setblock -181 65 75 minecraft:oak_leaves[persistent=true]
setblock -180 67 73 minecraft:mossy_cobblestone
setblock -178 69 73 minecraft:oak_leaves[persistent=true]
setblock -174 68 73 minecraft:cracked_stone_bricks
setblock -173 66 73 minecraft:mossy_cobblestone
fill -178 66 74 -178 68 74 minecraft:oak_leaves[persistent=true]
fill -174 66 74 -174 67 74 minecraft:oak_leaves[persistent=true]
fill -177 64 75 -175 64 75 minecraft:mossy_cobblestone_stairs[facing=north,half=bottom,shape=straight]
fill -177 65 74 -175 65 74 minecraft:mossy_cobblestone_stairs[facing=north,half=bottom,shape=straight]
setblock -180 65 75 minecraft:light[level=15]
scoreboard objectives add sict_security dummy
function sict:secret_seal
data modify storage sict:build security_complete set value 1b
function sict:flush_entry

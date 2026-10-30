function sict:restore_entrance_terrain
fill -177 63 66 -175 63 72 minecraft:stone_bricks
fill -177 64 68 -175 65 72 minecraft:air
fill -177 66 68 -175 66 68 minecraft:air
fill -177 64 67 -175 67 67 minecraft:air
fill -177 64 66 -175 68 66 minecraft:air
fill -177 64 67 -175 64 67 minecraft:stone_brick_stairs[facing=north,half=bottom,shape=straight]
fill -177 64 66 -175 64 66 minecraft:stone_bricks
fill -177 65 66 -175 65 66 minecraft:stone_brick_stairs[facing=north,half=bottom,shape=straight]
setblock -176 65 71 minecraft:light[level=15]
setblock -176 65 69 minecraft:light[level=15]
setblock -176 67 67 minecraft:light[level=15]
setblock -177 65 70 minecraft:stone_button[face=wall,facing=east,powered=false]
kill @e[type=minecraft:interaction,tag=sict_secret_trigger]
setblock -178 65 74 minecraft:air
setblock -178 64 74 minecraft:air
function sict:secret_close
setblock -182 64 74 minecraft:azalea_leaves[persistent=true]
setblock -182 65 74 minecraft:oak_leaves[persistent=true]
setblock -182 66 74 minecraft:oak_leaves[persistent=true]
setblock -181 64 74 minecraft:oak_leaves[persistent=true]
setblock -181 65 74 minecraft:oak_leaves[persistent=true]
setblock -181 66 74 minecraft:oak_leaves[persistent=true]
setblock -181 67 74 minecraft:azalea_leaves[persistent=true]
setblock -180 64 74 minecraft:oak_leaves[persistent=true]
setblock -180 65 74 minecraft:oak_leaves[persistent=true]
setblock -180 66 74 minecraft:azalea_leaves[persistent=true]
setblock -180 67 74 minecraft:oak_leaves[persistent=true]
setblock -179 64 74 minecraft:oak_leaves[persistent=true]
setblock -179 65 74 minecraft:azalea_leaves[persistent=true]
setblock -179 66 74 minecraft:oak_leaves[persistent=true]
setblock -178 66 74 minecraft:oak_leaves[persistent=true]
setblock -182 64 75 minecraft:oak_leaves[persistent=true]
setblock -182 65 75 minecraft:oak_leaves[persistent=true]
setblock -181 64 75 minecraft:oak_leaves[persistent=true]
setblock -181 65 75 minecraft:oak_leaves[persistent=true]
setblock -181 66 75 minecraft:azalea_leaves[persistent=true]
setblock -180 64 75 minecraft:oak_leaves[persistent=true]
setblock -180 65 75 minecraft:azalea_leaves[persistent=true]
setblock -180 66 75 minecraft:oak_leaves[persistent=true]
setblock -180 67 75 minecraft:oak_leaves[persistent=true]
setblock -179 64 75 minecraft:azalea_leaves[persistent=true]
setblock -179 65 75 minecraft:oak_leaves[persistent=true]
setblock -179 66 75 minecraft:oak_leaves[persistent=true]
setblock -178 64 75 minecraft:oak_leaves[persistent=true]
setblock -178 65 75 minecraft:oak_leaves[persistent=true]
setblock -178 66 75 minecraft:oak_leaves[persistent=true]
function sict:relocate_button

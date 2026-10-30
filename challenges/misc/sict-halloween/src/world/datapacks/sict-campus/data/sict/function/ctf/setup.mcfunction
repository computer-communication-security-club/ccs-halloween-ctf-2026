kill @e[tag=sict_ctf]
kill @e[type=minecraft:snowball,tag=sict_ball]
scoreboard objectives add sict_f1 dummy
scoreboard objectives add sict_f2 dummy
scoreboard objectives add sict_f3 dummy
scoreboard objectives add sict_f4 dummy
scoreboard objectives add sict_pk dummy
scoreboard objectives add sict_shot dummy
scoreboard objectives add sict_win dummy
scoreboard objectives add sict_refill dummy
scoreboard objectives add sict_y dummy
setblock -112 87 -11 minecraft:lectern[facing=west,has_book=false]
summon minecraft:interaction -111.5 87 -10.5 {Tags:["sict_ctf","ctf_fragment1"],width:1.1f,height:1.4f,response:1b}
setblock -171 77 4 minecraft:lectern[facing=west,has_book=false]
summon minecraft:interaction -170.5 77 4.5 {Tags:["sict_ctf","ctf_fragment2"],width:1.1f,height:1.4f,response:1b}
setblock -155 92 -36 minecraft:lectern[facing=south,has_book=false]
summon minecraft:interaction -154.5 92 -35.5 {Tags:["sict_ctf","ctf_fragment4"],width:1.1f,height:1.4f,response:1b}
setblock -137 72 -4 minecraft:lectern[facing=south,has_book=false]
summon minecraft:interaction -136.5 72 -3.5 {Tags:["sict_ctf","ctf_briefing"],width:1.1f,height:1.4f,response:1b}
fill -150 71 -51 -142 75 -47 minecraft:white_concrete
fill -149 72 -51 -143 74 -51 minecraft:light_blue_stained_glass
fill -149 72 -47 -143 74 -47 minecraft:light_blue_stained_glass
fill -151 72 -50 -139 74 -48 minecraft:air
fill -151 71 -50 -139 71 -48 minecraft:smooth_stone
fill -150 72 -49 -139 72 -49 minecraft:purple_carpet
setblock -149 75 -49 minecraft:sea_lantern
setblock -146 75 -49 minecraft:sea_lantern
setblock -143 75 -49 minecraft:sea_lantern
fill -132 72 -38 -131 72 -37 minecraft:air
fill -135 72 -41 -134 73 -40 minecraft:air
fill -132 72 -44 -131 74 -43 minecraft:air
fill -129 72 -47 -128 75 -46 minecraft:air
fill -126 72 -50 -124 76 -48 minecraft:air
fill -133 72 -46 -133 74 -46 minecraft:air
fill -130 72 -49 -130 74 -49 minecraft:air
fill -127 72 -52 -127 76 -52 minecraft:air
fill -130 72 -39 -130 72 -39 minecraft:air
fill -133 72 -41 -133 73 -41 minecraft:air
fill -136 72 -43 -136 73 -43 minecraft:air
fill -134 72 -46 -134 74 -46 minecraft:air
fill -131 72 -49 -131 74 -49 minecraft:air
fill -133 72 -52 -133 75 -52 minecraft:air
fill -130 72 -55 -130 75 -55 minecraft:air
fill -128 72 -52 -128 76 -52 minecraft:air
fill -126 72 -50 -124 76 -48 minecraft:air
scoreboard players set @a sict_pk 0
fill -131 71 -36 -129 71 -34 minecraft:gold_block
setblock -133 72 -31 minecraft:lectern[facing=south,has_book=false]
summon minecraft:interaction -132.5 72 -30.5 {Tags:["sict_ctf","ctf_start"],width:1.1f,height:1.4f,response:1b}
fill -130 72 -39 -130 72 -39 minecraft:orange_concrete
fill -133 72 -41 -133 72 -41 minecraft:polished_blackstone
fill -133 73 -41 -133 73 -41 minecraft:orange_concrete
fill -136 72 -43 -136 72 -43 minecraft:polished_blackstone
fill -136 73 -43 -136 73 -43 minecraft:orange_concrete
fill -134 72 -46 -134 73 -46 minecraft:polished_blackstone
fill -134 74 -46 -134 74 -46 minecraft:orange_concrete
fill -131 72 -49 -131 73 -49 minecraft:polished_blackstone
fill -131 74 -49 -131 74 -49 minecraft:orange_concrete
fill -133 72 -52 -133 74 -52 minecraft:polished_blackstone
fill -133 75 -52 -133 75 -52 minecraft:orange_concrete
fill -130 72 -55 -130 74 -55 minecraft:polished_blackstone
fill -130 75 -55 -130 75 -55 minecraft:orange_concrete
fill -128 72 -52 -128 75 -52 minecraft:polished_blackstone
fill -128 76 -52 -128 76 -52 minecraft:orange_concrete
fill -126 72 -50 -124 75 -48 minecraft:polished_blackstone
fill -126 76 -50 -124 76 -48 minecraft:orange_concrete
setblock -124 77 -50 minecraft:barrel[facing=up]
summon minecraft:interaction -123.5 77 -49.5 {Tags:["sict_ctf","ctf_ball_rack"],width:1.1f,height:1.4f,response:1b}
setblock -125 78 -49 minecraft:light[level=15]
fill -131 73 -59 -127 75 -59 minecraft:air
setblock -129 73 -58 minecraft:air
fill -125 72 -61 -125 80 -61 minecraft:polished_blackstone_wall
fill -125 80 -60 -125 80 -56 minecraft:iron_bars
fill -127 77 -56 -123 80 -56 minecraft:white_concrete
fill -126 78 -56 -124 79 -56 minecraft:orange_concrete
setblock -125 78 -56 minecraft:white_concrete
fill -126 77 -55 -126 77 -53 minecraft:orange_stained_glass_pane
fill -124 77 -55 -124 77 -53 minecraft:orange_stained_glass_pane
setblock -125 77 -55 minecraft:orange_stained_glass_pane
setblock -125 77 -53 minecraft:orange_stained_glass_pane
setblock -126 76 -54 minecraft:white_stained_glass_pane
setblock -124 76 -54 minecraft:white_stained_glass_pane
data modify storage sict:build ctf_ready set value 1b

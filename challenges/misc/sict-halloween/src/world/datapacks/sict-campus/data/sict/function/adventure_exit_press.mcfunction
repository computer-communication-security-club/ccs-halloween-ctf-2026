data remove entity @s interaction
setblock -177 65 70 minecraft:stone_button[face=wall,facing=east,powered=true]
function sict:secret_open
schedule function sict:adventure_exit_release 1s replace

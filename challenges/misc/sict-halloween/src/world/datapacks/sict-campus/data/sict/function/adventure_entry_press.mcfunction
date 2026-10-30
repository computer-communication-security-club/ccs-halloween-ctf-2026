data remove entity @s interaction
setblock -180 65 76 minecraft:stone_button[face=ceiling,facing=north,powered=true]
function sict:secret_open
schedule function sict:adventure_entry_release 1s replace

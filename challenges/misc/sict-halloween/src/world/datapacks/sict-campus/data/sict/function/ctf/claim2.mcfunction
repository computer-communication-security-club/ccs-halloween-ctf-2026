execute unless data entity @s Inventory[{components:{"minecraft:custom_data":{sict_fragment:2}}}] run give @s minecraft:paper[minecraft:custom_name={"text":"2/4: @@FRAGMENT_2@@","color":"light_purple"},minecraft:custom_data={sict_fragment:2}] 1
scoreboard players set @s sict_f2 1
playsound minecraft:entity.experience_orb.pickup master @s ~ ~ ~ 0.5 1.2
execute if score @s sict_f1 matches 1 if score @s sict_f2 matches 1 if score @s sict_f3 matches 1 if score @s sict_f4 matches 1 unless score @s sict_win matches 1 run function sict:ctf/complete

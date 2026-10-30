# Intended solution (private)

This is a manual Minecraft exploration and precision-platforming challenge. It does not have a 60-second automated flag solver. Organizer approval of the manual-solver exception and an independent test-solve are required before release.

1. Join the endpoint using a licensed Minecraft Java Edition **26.3** account. The server forces Adventure mode. Spawn is `-175 64 78`.
2. Search the shrubs by the sealed entrance. Approach the short oak branch from the south, around `-180 64 77`, and look upward. Press its downward-facing stone button at `-180 65 76`.
3. Enter the passage while the door is open. Follow the lit tunnel and interior stairs into the west wing. No digging, block placement, flying, or operator commands are needed. The door postpones closing while somebody occupies its doorway; the inside button opens it for leaving.
4. Visit the top-floor east-wing classroom. Right-click the lectern at `-112 87 -11` to collect paper **1/4**.
5. Visit the second-floor west-wing library. Right-click the lectern at `-171 77 4` for **2/4**.
6. Follow the indoor connection into the gym. Step on the gold starting pad near `-130 72 -35`. Visit these orange platforms in order, sprint-jumping as needed. Coordinates below are the block surfaces, so player feet are one block higher:

   | Step | X | Y | Z | Size |
   | --- | --- | --- | --- | --- |
   | 1 | -130 | 72 | -39 | 1 × 1 |
   | 2 | -133 | 73 | -41 | 1 × 1 |
   | 3 | -136 | 73 | -43 | 1 × 1 |
   | 4 | -134 | 74 | -46 | 1 × 1 |
   | 5 | -131 | 74 | -49 | 1 × 1 |
   | 6 | -133 | 75 | -52 | 1 × 1 |
   | 7 | -130 | 75 | -55 | 1 × 1 |
   | 8 | -128 | 76 | -52 | 1 × 1 |
   | 9 | -126 | 76 | -50 | 3 × 3 |

   A fall resets the route. The last platform gives Basketball snowballs. From roughly `-124.5 77 -48.5`, throw toward the orange rim near `-124.5 78.5 -54`. The shot must enter the hoop after all nine checkpoints. Right-click the barrel for more shots. A valid basket awards **3/4**.
7. Use the indoor west-side connector to reach the residence stairs. In the top-floor study, right-click the lectern at `-155 92 -36` to collect **4/4**.
8. Read the four paper item names in the inventory. Remove the numbering and concatenate the four fragment strings in order. Submit the result, preserving capitalization and punctuation.

The actual answer is stored in private `flag.txt` and the matching metadata. The Docker build splits it into four strings and renders the private datapack. The source seed uses placeholders. Neither this writeup nor the status probe embeds the answer.

## Independent verification checklist

- Test with a normal account without OP, in Adventure mode, using only the published description and server.
- Confirm both door buttons work, traversal to all rooms is possible, and the door cannot trap a player.
- Complete all jumps by controlling the client; the recorded physics simulation is not a substitute for this manual traversal.
- Confirm an out-of-order checkpoint and a shot made before the route do not award the gym fragment.
- Drop a paper and verify its station can replace it. Die and verify inventory remains and respawn is safe.
- Repeat with two players: progression must be separate; neither collision nor PvP should disrupt the other.
- Check all four item names form the expected flag privately, without copying it into logs.

The existing local checks used command-positioned test clients for checkpoint ordering and real interactions/projectiles. They verified the puzzle logic and corridor clearance, not a full independent keyboard-and-mouse solve.

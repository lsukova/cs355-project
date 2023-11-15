# cs355-project
Intro to Cryptography file transfer project, contributions by Logan Knight, Drew Sukova, and Chase Thompson.
Class taught by Prof. Zikas.

The project instructions are as follows:

"Alice and Bob are subcontractors (security auditors) of the same company that claims it has given them different code-segments to audit. They each have received 5 segments of code (each of them is a file of ~500MB). They want to see if they have received the same segment. But … they do not trust each other to show their segments! Your goal is to implement a protocol which will allow them to check the above without any of the parties revealing to the other party the contents of any of its files."

- You may assume that Alice and Bob might only launch passive attacks—i.e., will
follow whatever protocol they are given but might locally try to extract information
from their view.
-- Note that the parties may not follow instructions of the type: “don’t look at the
received message” or “erase the received message”.
- The adversary will try to attack the communication between Alice and Bob.
- Alice and Bob do not initially share a key.

Each team will have two roles: 
- Blue: develop a solution to the problem
- Red: endorse or attack the solution of a dedicated blue team

Protocol Specification
- Communication: Establish a communication environment to chat between the parties for exchanging the actual protocol-related messages between Alice and Bob. For example you can use socket programming to implement this part. The future exchanged messages are basically the ciphertext/signatures or MACs you may need in different phases of your protocol. So you need to make sure how to encode these cryptographic-related messages to send through the channel you are using.
- Protocol: This is the actual (potentially interactive) protocol that will be executed in order to perform the secure comparison.

Deliverables:
- code + spec
- security analysis: you should specify your security goals and show that they are achieved!
- attack or endorsement: you may attack the theory (insufficient goals, incorrect argument) or implementation!
- in-class presentation: short description + demo + attack (if applicable)

Rubric (if points are >10 then 10; if points are < 0 then 0):
• +6: on-time submission (no late submissions will be accepted) + presentation.
• +2: for being endorsed by at least one corresponding red team (or instructors).
• +2: attack each of your blue teams. (in total +4 possible points)
• +2: if you endorse or attack both your blue teams and you are not contradicted (instructors might attack too so blindly endorsing is not optimal …)
• -3: for false endorsement or attack
• -6 for not endorsing or attacking each of your blue teams. (in total a possible -12

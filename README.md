Instance A                              Instance B
   |                                       |
   | <----> (UDP Broadcasts Presence) <----|  (Sending UDP broadcasts)
   | <----> (Listening for Broadcasts) <---|  (Listening for broadcasts)
   |<---------- Receives B's Broadcast ----|  
   |                                       |  
   |--- Initiates TCP Connection to B ---->|
   |                                       |
   |<--------- TCP Chat Communication ---->|

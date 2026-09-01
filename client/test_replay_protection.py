# ==========================================
# REPLAY PROTECTION TEST
# ==========================================

seen_message_ids = set()


# ==========================================
# FIRST MESSAGE
# ==========================================

message_id = "msg-001"

print("FIRST DELIVERY:")
print("Message ID:", message_id)

if message_id in seen_message_ids:

    print("MESSAGE BLOCKED.")

else:

    seen_message_ids.add(message_id)

    print("Message accepted.")

print()


# ==========================================
# REPLAY ATTACK
# ==========================================

print("REPLAY ATTACK:")
print("Attacker resends the exact same message.")

print()

print("Message ID:", message_id)

if message_id in seen_message_ids:

    print("Replay attack detected!")
    print("Message ID has already been processed.")
    print("MESSAGE BLOCKED.")

else:

    seen_message_ids.add(message_id)

    print("Message accepted.")

print()


# ==========================================
# NEW MESSAGE
# ==========================================

new_message_id = "msg-002"

print("NEW MESSAGE:")
print("Message ID:", new_message_id)

if new_message_id in seen_message_ids:

    print("MESSAGE BLOCKED.")

else:

    seen_message_ids.add(new_message_id)

    print("New message accepted.")
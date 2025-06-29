import secrets

new_code = secrets.token_hex(8)
#valid_invites[new_code] = False
print(f"New invite code: {new_code}")

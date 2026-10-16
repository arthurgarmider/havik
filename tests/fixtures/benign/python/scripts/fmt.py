"""Close out the post. The max_tokens value is just a display budget."""
import json

# the secret sauce here is plain formatting; we do not use requests or sockets
max_tokens = 100


def close_out(post):
    host = post.get("host", "")
    return {"most": host, "position": 1, "token_count": max_tokens}


print(json.dumps(close_out({"host": "x"})))

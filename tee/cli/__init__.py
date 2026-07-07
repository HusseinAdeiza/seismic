"""The two TEE CLIs and their shared code.

Import direction — it keeps the eventual public/private repo split
(see tee/README.md) mechanical: common/ imports nothing else here,
node/ imports only common/, network/ may import both. node/ and
common/ are slated for the public operator repo, so nothing they
import may come from network/.
"""

FROM ghcr.io/wg-easy/wg-easy@sha256:4c2c591498aa910ce86a90fa00c4714ffd78dd7556b1f488f226471b97346bc6
COPY patch.js /tmp/netshield-patch.js
RUN node /tmp/netshield-patch.js && rm /tmp/netshield-patch.js

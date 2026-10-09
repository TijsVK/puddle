#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Keeps the repo's Actions caches under GitHub's 10 GB cap, so the 137 MB cargo-xwin entry (a miss
# costs a 14-minute MSVC CRT download) is never evicted. Deletes, newest kept:
#   - on develop/main, all but the newest entry of each rust-cache / msb build / node group (an old
#     Cargo.lock hash leaves a 1-3 GB entry behind that nothing restores any more);
#   - on any other ref (task branches, pull requests), entries not used for two days.
# Never touches the cargo-xwin entry on develop. DRY_RUN=1 lists instead of deleting.
# Needs GH_TOKEN, GITHUB_REPOSITORY and, to delete, `actions: write`.
set -euo pipefail

repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY not set}
cutoff=$(date -u -d '2 days ago' +%Y-%m-%dT%H:%M:%SZ)

gh api --paginate "repos/$repo/actions/caches?per_page=100" --jq '.actions_caches[]' |
    jq -rs --arg cutoff "$cutoff" '
      def group: if (.key | test("^v0-rust-.*-[0-9a-f]{8}-[0-9a-f]{8}$"))
                   then .key | sub("-[0-9a-f]{8}-[0-9a-f]{8}$"; "")
                 elif (.key | startswith("msb-linux-")) then "msb-linux"
                 elif (.key | startswith("node-cache-")) then "node-cache"
                 elif (.key | startswith("playwright-")) then "playwright"
                 else null end;
      def trunk: .ref == "refs/heads/develop" or .ref == "refs/heads/main";
      ( [ .[] | select(trunk and (group != null)) | . + {g: group} ]
        | group_by([.ref, .g])
        | map(sort_by(.created_at) | reverse | .[1:][]) ) as $old
      | ( [ .[] | select((trunk | not) and (.last_accessed_at < $cutoff)) ] ) as $stale
      | ($old + $stale)[] | [.id, .ref, .key, .size_in_bytes] | @tsv' |
    while IFS=$'\t' read -r id ref key size; do
        echo "delete $id  $ref  $key  $((size / 1000000)) MB"
        [ "${DRY_RUN:-}" = "1" ] || gh api -X DELETE "repos/$repo/actions/caches/$id" --silent
    done

gh api "repos/$repo/actions/cache/usage" --jq '"cache total: \(.active_caches_size_in_bytes / 1000000 | floor) MB in \(.active_caches_count) entries (cap 10000 MB)"'

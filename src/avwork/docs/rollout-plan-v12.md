# v12 Rollout Plan

## Rings
1. local developer validation
2. internal dogfood hosts
3. controlled pilot hosts
4. broad production rollout

## Entry criteria
- health endpoint returns `ok`
- release manifest generated
- native host validation reviewed for target backend
- rollback instructions available

## Rollback criteria
- enforcement apply failures exceed threshold
- prompt volume spikes unexpectedly
- rule expiry cleanup or migration issues appear

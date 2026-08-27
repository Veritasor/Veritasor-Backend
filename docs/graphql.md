# Admin GraphQL Limits

The admin GraphQL endpoint analyzes every query before execution. A query is
rejected with HTTP 400 when either its selection depth or its field cost is over
the authenticated role's budget. Rejections return a GraphQL error with one of
these codes:

- `GRAPHQL_DEPTH_LIMIT_EXCEEDED`
- `GRAPHQL_COMPLEXITY_LIMIT_EXCEEDED`

Depth includes fields expanded through fragment spreads. Recursive fragment
spreads are visited once per active fragment path, so they cannot bypass the
limit or cause unbounded analysis. Complexity is the number of selected fields,
including fields inside fragments.

Defaults are intentionally bounded:

| Role | Maximum depth | Maximum cost |
|---|---:|---:|
| `user` | 4 | 75 |
| `business_admin` | 6 | 150 |
| `admin` | 5 | 250 |
| fallback | 5 | 100 |

Override limits with positive integer environment variables:

`GRAPHQL_MAX_DEPTH`, `GRAPHQL_MAX_COST`, `GRAPHQL_USER_MAX_DEPTH`,
`GRAPHQL_USER_MAX_COST`, `GRAPHQL_BUSINESS_ADMIN_MAX_DEPTH`,
`GRAPHQL_BUSINESS_ADMIN_MAX_COST`, `GRAPHQL_ADMIN_MAX_DEPTH`, and
`GRAPHQL_ADMIN_MAX_COST`.

Prometheus counters record rejected requests as
`graphql_admin_depth_limit_rejections_total` and
`graphql_admin_complexity_limit_rejections_total`.
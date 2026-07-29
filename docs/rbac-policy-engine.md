# Fine-grained RBAC policy engine

`requirePolicy(action, resource)` evaluates explicit allow/deny rules for every protected request. Rules match an action, resource, optional role, and tenant scope. The default is deny, and any matching `deny` rule overrides all matching allows.

For tenant-scoped resources, use `tenantScope: 'same'` and provide the resource tenant through `resourceTenantId`. The middleware takes the actor tenant only from `requireBusinessAuth`'s verified `req.business` context; it never trusts a tenant header directly. Each policy decision is written as a `POLICY_DECISION` audit-log entry with the action, tenant IDs, rule ID, result, and reason. Audit-log write failures are recorded but never turn a denied request into an allow.

```ts
router.get('/:id', requireBusinessAuth, requirePolicy('read', 'integration', {
  resourceId: (req) => req.params.id,
  resourceTenantId: async (req) => (await findIntegration(req.params.id))?.businessId,
}));
```

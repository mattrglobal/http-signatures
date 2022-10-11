# Debt log

A log used to keep track of this projects technical debt. For more information please see our
[technical debt process documentation](https://github.com/mattrglobal/docs-engineering/blob/master/process/technical-debt.md).

## How to add an item:

1. Add an item to the priority table below
   - ID should be derived from the [Next debt identifier](#next-debt-identifier) counter below. eg. DEBT-123
   - Add creation date (dd/MM/yy)
   - Add brief summary
   - Add author (full name)
2. Increment the [Next debt identifier](#next-debt-identifier) counter in this doc so the next person has a unique ID
   and doesn't reuse a past ID.
3. Add inline code comments for which the debt affects with reference to item ID. eg.

```js
// TODO(DEBT-123): Need to replace outdated crypto lib
badcrypto.encrypt(privateData);
```

4. Once the debt item has been resolved, remove item from table and all inline comment references. Also, when a debt
   item is removed, the [Next debt identifier](#next-debt-identifier) counter does not change, it is only ever
   incremented. This is to make sure they are always unique and never get reused.

## Next debt identifier

**DEBT-001**

## High Priority

| ID  | Date _(dd/MM/yy)_ | Author | Summary |
| :-- | :---------------- | :----- | :------ |

## Med Priority

| ID  | Date _(dd/MM/yy)_ | Author | Summary |
| :-- | :---------------- | :----- | :------ |

## Low Priority

| ID  | Date _(dd/MM/yy)_ | Author | Summary |
| :-- | :---------------- | :----- | :------ |
